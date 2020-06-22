# The Exploit Database Git Repository

This is an official repository of [The Exploit Database](https://www.exploit-db.com/), a [project](https://www.offensive-security.com/community-projects/) sponsored by [Offensive Security](https://www.offensive-security.com/).
Our repositories are:

  - Exploits & Shellcodes: [https://github.com/offensive-security/exploitdb](https://github.com/offensive-security/exploitdb)
  - Binary Exploits: [https://github.com/offensive-security/exploitdb-bin-sploits](https://github.com/offensive-security/exploitdb-bin-sploits)
  - Papers: [https://github.com/offensive-security/exploitdb-papers](https://github.com/offensive-security/exploitdb-papers)

The Exploit Database is an archive of public exploits and corresponding vulnerable software, developed for use by penetration testers and vulnerability researchers. Its aim is to serve as the most comprehensive collection of [exploits](https://www.exploit-db.com/), [shellcode](https://www.exploit-db.com/shellcodes) and [papers](https://www.exploit-db.com/papers) gathered through direct submissions, mailing lists, and other public sources, and present them in a freely-available and easy-to-navigate database. The Exploit Database is a repository for exploits and Proof-of-Concepts rather than advisories, making it a valuable resource for those who need actionable data right away.
You can learn more about the project [here (Top Right -> About Exploit-DB)](https://www.exploit-db.com/) and [here (History)](https://www.exploit-db.com/history).

This repository is updated daily with the most recently added submissions. Any additional resources can be found in our [binary exploits repository](https://github.com/offensive-security/exploitdb-bin-sploits).

Exploits are located in the [`/exploits/`](https://github.com/offensive-security/exploitdb/tree/master/exploits) directory, shellcodes can be found in the [`/shellcodes/`](https://github.com/offensive-security/exploitdb/tree/master/shellcodes) directory.

- - -

## License

This project (and SearchSploit) is released under "[GNU General Public License v2.0](https://github.com/offensive-security/exploitdb/blob/master/LICENSE.md)".

- - -

# SearchSploit

Included with this repository is the **SearchSploit** utility, which will allow you to search through exploits, shellcodes and papers _(if installed)_ using one or more terms.
For more information, please see the **[SearchSploit manual](https://www.exploit-db.com/searchsploit)**.

## Usage/Example

```
kali@kali:~$ searchsploit -h
  Usage: searchsploit [options] term1 [term2] ... [termN]

==========
 Examples
==========
  searchsploit afd windows local
  searchsploit -t oracle windows
  searchsploit -p 39446
  searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"
  searchsploit -s Apache Struts 2.0.0
  searchsploit linux reverse password
  searchsploit -j 55555 | json_pp

  For more examples, see the manual: https://www.exploit-db.com/searchsploit

=========
 Options
=========
## Search Terms
   -c, --case     [Term]      Perform a case-sensitive search (Default is inSEnsITiVe)
   -e, --exact    [Term]      Perform an EXACT & order match on exploit title (Default is an AND match on each term) [Implies "-t"]
                                e.g. "WordPress 4.1" would not be detect "WordPress Core 4.1")
   -s, --strict               Perform a strict search, so input values must exist, disabling fuzzy search for version range
                                e.g. "1.1" would not be detected in "1.0 < 1.3")
   -t, --title    [Term]      Search JUST the exploit title (Default is title AND the file's path)
       --exclude="term"       Remove values from results. By using "|" to separate, you can chain multiple values
                                e.g. --exclude="term1|term2|term3"

## Output
   -j, --json     [Term]      Show result in JSON format
   -o, --overflow [Term]      Exploit titles are allowed to overflow their columns
   -p, --path     [EDB-ID]    Show the full path to an exploit (and also copies the path to the clipboard if possible)
   -v, --verbose              Display more information in output
   -w, --www      [Term]      Show URLs to Exploit-DB.com rather than the local path
       --id                   Display the EDB-ID value rather than local path
       --colour               Disable colour highlighting in search results

## Non-Searching
   -m, --mirror   [EDB-ID]    Mirror (aka copies) an exploit to the current working directory
   -x, --examine  [EDB-ID]    Examine (aka opens) the exploit using $PAGER

## Non-Searching
   -h, --help                 Show this help screen
   -u, --update               Check for and install any exploitdb package updates (brew, deb & git)

## Automation
       --nmap     [file.xml]  Checks all results in Nmap's XML output with service version
                                e.g.: nmap [host] -sV -oX file.xml

=======
 Notes
=======
 * You can use any number of search terms
 * By default, search terms are not case-sensitive, ordering is irrelevant, and will search between version ranges
   * Use '-c' if you wish to reduce results by case-sensitive searching
   * And/Or '-e' if you wish to filter results by using an exact match
   * And/Or '-s' if you wish to look for an exact version match
 * Use '-t' to exclude the file's path to filter the search results
   * Remove false positives (especially when searching using numbers - i.e. versions)
 * When using '--nmap', adding '-v' (verbose), it will search for even more combinations
 * When updating or displaying help, search terms will be ignored

kali@kali:~$
kali@kali:~$ searchsploit afd windows local
---------------------------------------------------------------------------------------- -----------------------------------
 Exploit Title                                                                          |  Path
---------------------------------------------------------------------------------------- -----------------------------------
Microsoft Windows (x86) - 'afd.sys' Local Privilege Escalation (MS11-046)               | windows_x86/local/40564.c
Microsoft Windows - 'afd.sys' Local Kernel (PoC) (MS11-046)                             | windows/dos/18755.c
Microsoft Windows - 'AfdJoinLeaf' Local Privilege Escalation (MS11-080) (Metasploit)    | windows/local/21844.rb
Microsoft Windows 7 (x64) - 'afd.sys' Dangling Pointer Privilege Escalation (MS14-040)  | windows_x86-64/local/39525.py
Microsoft Windows 7 (x86) - 'afd.sys' Dangling Pointer Privilege Escalation (MS14-040)  | windows_x86/local/39446.py
Microsoft Windows XP - 'afd.sys' Local Kernel Denial of Service                         | windows/dos/17133.c
Microsoft Windows XP/2003 - 'afd.sys' Local Privilege Escalation (K-plugin) (MS08-066)  | windows/local/6757.txt
Microsoft Windows XP/2003 - 'afd.sys' Local Privilege Escalation (MS11-080)             | windows/local/18176.py
---------------------------------------------------------------------------------------- -----------------------------------
Shellcodes: No Result
kali@kali:~$
kali@kali:~$ searchsploit -p 39446
  Exploit: Microsoft Windows 7 (x86) - 'afd.sys' Dangling Pointer Privilege Escalation (MS14-040)
      URL: https://www.exploit-db.com/exploits/39446
     Path: /usr/share/exploitdb/exploits/windows_x86/local/39446.py
File Type: Python script, ASCII text executable, with CRLF line terminators

Copied EDB-ID #39446's path to the clipboard.
kali@kali:~$
```

- - -

## Install

SearchSploit requires either "CoreUtils" or "utilities" (e.g. `bash`, `sed`, `grep`, `awk`, etc.) for the core features to work.
The self updating function will require `git`, and for the Nmap XML option to work, will require `xmllint` (found in the `libxml2-utils` package in Debian-based systems).

You can find a **more in-depth guide in the [SearchSploit manual](https://www.exploit-db.com/searchsploit)**.

**Kali Linux**

Exploit-DB/SearchSploit is already packaged inside of Kali-Linux. A method of installation is:

```
kali@kali:~$ sudo apt -y install exploitdb
```

_NOTE: Optional is to install the additional packages:_

```
kali@kali:~$ sudo apt -y install exploitdb-bin-sploits exploitdb-papers
```

**Git**

In short: clone the repository, add the binary into `$PATH`, and edit the config file to reflect the git path:

```
$ sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
$ sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
```

**Homebrew**

If you have [homebrew](http://brew.sh/) ([package](https://github.com/Homebrew/homebrew-core/blob/master/Formula/exploitdb.rb), [formula](https://formulae.brew.sh/formula/exploitdb)) installed, running the following will get you set up:

```
user@MacBook:~$ brew update && brew install exploitdb
```

- - -

## Credit

The following people made this possible:

- [Offensive Security](https://www.offensive-security.com/)
- [Unix-Ninja](https://github.com/unix-ninja)
- [g0tmi1k](https://blog.g0tmi1k.com/)
