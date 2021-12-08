##
# $Id: messagebox.rb 4 2010-02-26 00:28:00:00Z corelanc0d3r & rick2600 $
##
#
#  Installation instructions :
#  Drop file in framework3/modules/payloads/singles/windows folder
#
# Usage :   ./msfpayload windows/messagebox TITLE="Corelan" TEXT="Greetz to corelanc0d3r" P
#

require 'msf/core'
module Metasploit3

include Msf::Payload::Windows
include Msf::Payload::Single

  def initialize(info = {})
      super(update_info(info,
       'Name'          => 'Windows Messagebox with custom title and text',
       'Version'       => '$Revision: 4 $',
       'Description'   => 'Spawns MessageBox with a customizable title & text',
       'Author'        => [ 'corelanc0d3r - peter.ve[at]corelan.be',
                                'rick2600 - ricks2600[at]gmail.com' ],
       'License'       => BSD_LICENSE,
       'Platform'      => 'win',
       'Arch'          => ARCH_X86,
       'Privileged'    => false,
       'Payload'       =>
               {
               'Offsets' => { },
               'Payload' =>    "\xd9\xeb\x9b\xd9\x74\x24\xf4\x31"+
                               "\xd2\xb2\x7a\x31\xc9\x64\x8b\x71"+
                               "\x30\x8b\x76\x0c\x8b\x76\x1c\x8b"+
                               "\x46\x08\x8b\x7e\x20\x8b\x36\x38"+
                               "\x4f\x18\x75\xf3\x59\x01\xd1\xff"+
                               "\xe1\x60\x8b\x6c\x24\x24\x8b\x45"+
                               "\x3c\x8b\x54\x05\x78\x01\xea\x8b"+
                               "\x4a\x18\x8b\x5a\x20\x01\xeb\xe3"+
                               "\x37\x49\x8b\x34\x8b\x01\xee\x31"+
                               "\xff\x31\xc0\xfc\xac\x84\xc0\x74"+
                               "\x0a\xc1\xcf\x0d\x01\xc7\xe9\xf1"+
                               "\xff\xff\xff\x3b\x7c\x24\x28\x75"+
                               "\xde\x8b\x5a\x24\x01\xeb\x66\x8b"+
                               "\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b"+
                               "\x04\x8b\x01\xe8\x89\x44\x24\x1c"+
                               "\x61\xc3\xb2\x08\x29\xd4\x89\xe5"+
                               "\x89\xc2\x68\x8e\x4e\x0e\xec\x52"+
                               "\xe8\x9c\xff\xff\xff\x89\x45\x04"+
                               "\xbb"
                        }
                        ))

                # EXITFUNC : Only support Process and Thread :/
                deregister_options('EXITFUNC')

                # Register MessageBox options
                register_options(
                     [
                      OptString.new('EXITFUNC', [ false,
              "Only Process (default) or Thread are supported","process"]),
                      OptString.new('TITLE', [ true,
                                   "Messagebox Title (max 255 chars)" ]),
                      OptString.new('TEXT', [ true,
                                   "Messagebox Text" ])
                      ], self.class)
        end

    #
    # Constructs the payload
    #
   def generate

     strExitFunc = datastore['EXITFUNC'] || "process"
     strExitFuncHash = "\x7e\xd8\xe2\x73"   #ExitProcess()

     strTitle = datastore['TITLE']
      if (strTitle)

       #ExitFunc
       if (strExitFunc) then
         strExitFunc=strExitFunc.downcase
         if strExitFunc == "thread" then
           strExitFuncHash="\xEF\xCE\xE0\x60"   #ExitThread()
         end
       end

       #================Process Title==================================
       strTitle=strTitle+"X"
       iTitle=strTitle.length
       if (iTitle < 256)
         iNrLines=iTitle/4
         iCheckChars = iNrLines * 4
         strSpaces=""
         iSniperTitle=iTitle-1
         if iCheckChars != iTitle then
           iTargetChars=(iNrLines+1)*4
           while iTitle < iTargetChars
             strSpaces+=" "         #add space
             iTitle+=1
           end
         end
         strTitle=strTitle+strSpaces   #title is now 4 byte aligned
                                       #and string ends with X
                                       #at index iSniperTitle

         #push Title to stack
         #start at back of string
         strPushTitle=""
         strLine=""
         icnt=strTitle.length-1
         icharcnt=0
         while icnt >= 0
           thisChar=strTitle[icnt,1]
           strLine=thisChar+strLine
           if icharcnt < 3
            icharcnt+=1
           else
            strPushTitle=strPushTitle+"h"+strLine    #h = \68 = push
            strLine=""
            icharcnt=0
           end
           icnt=icnt-1
         end

         #generate opcode to write null byte
         strWriteTitleNull="\x31\xDB\x88\x5C\x24"
         strWriteTitleNull += iSniperTitle.chr + "\x89\xe3"


         #================Process Text===============================
         #cut text into 4 byte push instructions
         strText = datastore['TEXT']
         strText=strText+"X"
         iText=strText.length
         iNrLines=iText/4
         iCheckChars = iNrLines * 4
         strSpaces=""
         iSniperText=iText-1
         if iCheckChars != iText then
           iTargetChars=(iNrLines+1)*4
           while iText < iTargetChars
               strSpaces+=" "         #add space
               iText+=1
           end
         end
         strText=strText+strSpaces   #text is now 4 byte aligned
                                     #and string ends with X
                                     #at index iSniperTitle

        #push Text to stack
        #start at back of string
        strPushText=""
        strLine=""
        icnt=strText.length-1
        icharcnt=0
        while icnt >= 0
          thisChar=strText[icnt,1]
          strLine=thisChar+strLine
          if icharcnt < 3
             icharcnt+=1
          else
             strPushText=strPushText+"h"+strLine  #h = \68 = push
             strLine=""
             icharcnt=0
          end
          icnt=icnt-1
        end

        #generate opcode to write null byte
        strWriteTextNull="\x31\xc9\x88\x4C\x24"
        strWriteTextNull += iSniperText.chr + "\x89\xe1"


        #build payload
        payload_data = module_info['Payload']['Payload']
        payload_data += strExitFuncHash
        payload_data += "\x87\x1c\x24"
        payload_data += "\x52\xe8\x8b\xff\xff\xff\x89\x45"
        payload_data += "\x08\x68\x6c\x6c\x20\xff\x68\x33"
        payload_data += "\x32\x2e\x64\x68\x75\x73\x65\x72"
        payload_data += "\x88\x5c\x24\x0a\x89\xe6\x56\xff"
        payload_data += "\x55\x04\x89\xc2\x50\xbb\xa8\xa2"
        payload_data += "\x4d\xbc\x87\x1c\x24\x52\xe8\x5e"
        payload_data += "\xff\xff\xff"
        payload_data += strPushTitle + strWriteTitleNull
        payload_data += strPushText + strWriteTextNull
        payload_data += "\x31\xd2\x52"
        payload_data += "\x53\x51\x52\xff\xd0\x31\xc0\x50"
        payload_data += "\xff\x55\x08"


        return payload_data
       else
         raise ArgumentError, "Title should be 255 characters or less"
       end
     end
   end
end