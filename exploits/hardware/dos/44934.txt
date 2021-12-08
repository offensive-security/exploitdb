# Exploit Title: DIGISOL DG-BR4000NG - Buffer Overflow (PoC)
# Date 2018-06-24
# Vendor Homepage† http://www.digisol.com
# Hardware Link httpswww.amazon.inDigisol-DG-BR4000NG-Wireless-Broadband-802-11ndpB00A19EHYK
# Version: DIGISOL DG-BR4000NG Wireless Router
# Category Hardware
# Exploit Author Adipta Basu
# Tested on Mac OS High Sierra
# CVE CVE-2018-12706

# Reproduction Steps

- Goto your Wifi Router Gateway [i.e http192.168.2.1]
- Go to -- General Setup -- Wireless -- Basic Settings
- Open BurpSuite
- Reload the Page
- Burp will capture the intercepts.
- Add a string of 500 ì0îs after the Authorization Basic string
- The router will restart.
- Refresh the page, and the whole web interface will be faulty.