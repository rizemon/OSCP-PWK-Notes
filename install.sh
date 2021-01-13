#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

: '
+--------------------+
|     Tool name      |
+--------------------+
| docker-ce          |
| rlwrap             |
| code               |
| gobuster           |
| openjdk-11-jdk     |
| gdb                |
| ffuf               |
| seclists           |
| telnet             |
| cmake              |
| mingw-w64          |
| crowbar            |
| mariadb-client     |
| rustscan           |
| pip2               |
| pip3               |
| evil-winrm         |
| feroxbuster        |
| autorecon          |
| updog              |
| sherlock           |
| empire             |
| msfpc              |
| sudo_killer        |
| les                |
| wesng              |
| powerless          |
| seatbelt           |
| powerview          |
| rsg                |
| windapsearch       |
| linenum.sh         |
| lse.sh             |
| winpeas            |
| linpeas            |
| volatility         |
| nishang            |
| ghidra             |
| sysinternals suite |
| juicypotato        |
| roguepotato        |
| pwntools           |
| z3-solver          |
| randcrack          |
| ms17-010           |
| sambacry           |
| ghostcat           |
| postfix shellshock |
| xploit_installer   |
| windows-binaries   |
| static-binaries    |          
+--------------------+
'

# Install manually:
# Wappalyzer (https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)
# Cookie Quick Manager (https://addons.mozilla.org/en-US/firefox/addon/cookie-quick-manager/)
# FoxyProxy Standard (https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)

# Install keys

## Add Docker keys
curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | tee /etc/apt/sources.list.d/docker.list
## Add VSCode keys
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" | tee /etc/apt/sources.list.d/vscode.list

# Update
apt-get update -y && apt-get dist-upgrade -y

# Update searchsploit
searchsploit -u

# Install packages

packagelist=(
	docker-ce
	rlwrap
	code
	gobuster
	openjdk-11-jdk
	gdb
	ffuf
	seclists
	telnet
	cmake
	mingw-w64
    crowbar
	mariadbclient
)

apt-get install -y ${packagelist[@]}

# Configure auto-startup for Docker
systemctl enable docker
systemctl start docker
usermod -aG docker kali

# Install https://github.com/RustScan/RustScan
docker pull rustscan/rustscan:2.0.0
echo "alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:2.0.0'" | tee -a /home/kali/.zshrc /root/.zshrc

# Install pip2 and pip3

curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
python2 /tmp/get-pip.py
python3 /tmp/get-pip.py

# Tools
mkdir /home/kali/Desktop/tools
cd /home/kali/Desktop/tools

# Important directories
ln -s /usr/share/seclists /home/kali/Desktop/tools/seclists
ln -s /usr/share/wordlists /home/kali/Desktop/tools/wordlists
ln -s /usr/share/nmap/scripts/ /home/kali/Desktop/tools/nmap-scripts
ln -s /usr/share/webshells /home/kali/Desktop/tools/webshells

# Install evil-winrm
gem install evil-winrm

# Install feroxbuster
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash
mv feroxbuster /usr/bin/feroxbuster

# Install AutoRecon
python3 -m pip install git+https://github.com/Tib3rius/AutoRecon.git

# Install Updog
python3 -m pip install updog

# Install Sherlock
git clone https://github.com/rasta-mouse/Sherlock

# Install Empire
git clone https://github.com/EmpireProject/Empire

# Install msfpc
git clone https://github.com/g0tmi1k/msfpc

# Install SUDO_KILLER
git clone https://github.com/TH3xACE/SUDO_KILLER

# Install les
git clone https://github.com/mzet-/linux-exploit-suggester

# Install wesng
git clone https://github.com/bitsadmin/wesng

# Install Powerless
git clone https://github.com/M4ximuss/Powerless

# Install Seatbelt
mkdir Seatbelt
wget https://raw.githubusercontent.com/r3motecontrol/Ghostpack-CompiledBinaries/master/Seatbelt.exe -O Seatbelt/Seatbelt.exe

# Install Powerview
mkdir powerview
curl https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 > powerview/powerview.ps1

# Install rsg - Reverse Shell Generator
git clone https://github.com/mthbernardes/rsg

# Install windapsearch
git clone https://github.com/ropnop/windapsearch

# Install LinEnum.sh
git clone https://github.com/rebootuser/LinEnum

# Install Linux Smart Enumeraetion
git clone https://github.com/diego-treitos/linux-smart-enumeration

# Install winPEAS and linPEAS
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

# Install volatility
git clone https://github.com/volatilityfoundation/volatility3.git

# Install impacket for python2
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
python2 -m pip install setuptools
python2 -m pip install .
cd ..

# Install nishang
git clone https://github.com/samratashok/nishang

# Install Ghidra
curl https://ghidra-sre.org/ghidra_9.2_PUBLIC_20201113.zip > ghidra.zip
unzip ghidra.zip && rm ghidra.zip
mv ghidra_9.2_PUBLIC ghidra

# Download Sysinternals Suite
curl https://download.sysinternals.com/files/SysinternalsSuite.zip > sysinternals.zip
unzip sysinternals.zip -d sysinternals && rm sysinternals.zip

# Install pspy
mkdir pspy
curl -s https://api.github.com/repos/DominicBreuker/pspy/releases/latest | grep "browser_download_url.*pspy32\"" | cut -d : -f 2,3 | tr -d \" | wget -qi - -O pspy/pspy32
curl -s https://api.github.com/repos/DominicBreuker/pspy/releases/latest | grep "browser_download_url.*pspy64\"" | cut -d : -f 2,3 | tr -d \" | wget -qi - -O pspy/pspy64

# Install potatoes
mkdir potatoes
curl -s https://api.github.com/repos/ohpe/juicy-potato/releases/latest | grep "browser_download_url.*exe" | cut -d : -f 2,3 | tr -d \" | wget -qi - -O potatoes/juicypotato.exe
curl -s https://api.github.com/repos/antonioCoco/RoguePotato/releases/latest | grep "browser_download_url.*RoguePotato.zip\"" | cut -d : -f 2,3 | tr -d \" | wget -qi - -O potatoes/RoguePotato.zip && unzip potatoes/RoguePotato.zip -d potatoes && rm potatoes/RoguePotato.zip

# Install pwntools
python2 -m pip install pwntools
python3 -m pip install pwntools

# Install z3 solver
python2 -m pip install z3-solver
python3 -m pip install z3-solver

# Install randcrack
python2 -m pip install randcrack
python3 -m pip install randcrack
    
# Exploits
mkdir /home/kali/Desktop/exploits
cd /home/kali/Desktop/exploits

# MS17-010 (Eternal Blue) exploit
mkdir eternalblue
curl https://raw.githubusercontent.com/helviojunior/MS17-010/master/send_and_execute.py > eternalblue/ms17-010.py
curl https://raw.githubusercontent.com/worawit/MS17-010/master/mysmb.py > eternalblue/mysmb.py
curl https://raw.githubusercontent.com/worawit/MS17-010/master/checker.py > eternalblue/pipefinder.py

# mRemoteNG Password Decrypter
mkdir mremoteng
curl https://raw.githubusercontent.com/kmahyyg/mremoteng-decrypt/master/mremoteng_decrypt.py > mremoteng/decrypt.py

# CVE-2017-7494 SambaCry
git clone https://github.com/joxeankoret/CVE-2017-7494 sambacry

# CVE-2020-1938 Ghostcat
git clone https://github.com/dacade/CVE-2020-1938 ghostcat

# Postfix Shellshock
mkdir postfix_shellshock
curl https://gist.githubusercontent.com/claudijd/33771b6c17bc2e4bc59c/raw/4458302d966b640e0098bef7ad2d057ac06c4e27/exploit.py > postfix_shellshock/exploit.py

# xploit_installer
mkdir xploit_installer
curl https://raw.githubusercontent.com/wwong99/pentest-notes/master/scripts/xploit_installer.py > xploit_installer/xploit_installer.py

# Useful static binaries
mkdir /home/kali/Desktop/binaries
cd /home/kali/Desktop/binaries
ln -s /usr/share/windows-resources/ windows-binaries
git clone https://github.com/andrew-d/static-binaries


# Unzip rockyou.txt
gunzip /usr/share/wordlists/rockyou.txt

mkdir /home/kali/Desktop/web
cd /home/kali/Desktop/web

ln -s /home/kali/Desktop/tools/Empire/data/module_source/credentials/Invoke-Kerberoast.ps1 Invoke-Kerberoast.ps1
ln -s /home/kali/Desktop/tools/nishang/Gather/Invoke-Mimikatz.ps1 Invoke-Mimikatz.ps1
ln -s /home/kali/Desktop/tools/nishang/Shells/Invoke-PowerShellTcp.ps1 Invoke-PowerShellTcp.ps1

ln -s /home/kali/Desktop/tools/Powerless/Powerless.bat powerless.bat
ln -s /home/kali/Desktop/tools/powerview/powerview.ps1 powerview.ps1
ln -s /home/kali/Desktop/tools/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASbat/winPEAS.bat winpeas.bat
ln -s /home/kali/Desktop/tools/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/Obfuscated\ Releases/winPEASx86.exe winpeasx86.exe
ln -s /home/kali/Desktop/tools/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/Obfuscated\ Releases/winPEASx64.exe winpeasx64.exe
ln -s /home/kali/Desktop/tools/privilege-escalation-awesome-scripts-suite/winPEAS/winPEASexe/winPEAS/bin/Obfuscated\ Releases/winPEASany.exe winpeasany.exe
ln -s /home/kali/Desktop/tools/Sherlock/Sherlock.ps1 sherlock.ps1
ln -s /home/kali/Desktop/tools/Seatbelt/Seatbelt.exe seatbelt.exe

ln -s /home/kali/Desktop/tools/LinEnum/LinEnum.sh linenum.sh
ln -s /home/kali/Desktop/tools/linux-smart-enumeration/lse.sh lse.sh
ln -s /home/kali/Desktop/tools/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh linpeas.sh
ln -s /home/kali/Desktop/tools/pspy/pspy32 pspy32
ln -s /home/kali/Desktop/tools/pspy/pspy64 pspy64

ln -s /home/kali/Desktop/tools/potatoes/juicypotato.exe juicypotato.exe
ln -s /home/kali/Desktop/tools/potatoes/RoguePotato.exe roguepotato.exe

ln -s /home/kali/Desktop/tools/sysinternals sysinternals
ln -s /home/kali/Desktop/binaries/windows-binaries/binaries/nc.exe nc.exe
ln -s /home/kali/Desktop/binaries/windows-binaries/binaries/whoami.exe whoami.exe
ln -s /home/kali/Desktop/binaries/windows-binaries/binaries/plink.exe plink.exe
ln -s /home/kali/Desktop/binaries/windows-binaries/mimikatz/x64/mimikatz.exe mimikatz64.exe
ln -s /home/kali/Desktop/binaries/windows-binaries/mimikatz/Win32/mimikatz.exe mimikatz32.exe
ln -s /home/kali/Desktop/binaries/windows-binaries/mimikatz/Win32/mimilove.exe mimilove.exe

# Command Shortcuts

tee -a ~/.zshrc << END

resolve() {
	cat /etc/hosts | grep "\$1" | cut -d " " -f 1 
}

superscan() {
	name="\$(resolve \$1)"
	rustscan --accessible -a "\$name" -r 1-65535 -- -sT -sV -sC -Pn 
}
END

# Free RWX for all!
chmod -R 777 /home/kali/Desktop/tools
chmod -R 777 /home/kali/Desktop/exploits
chmod -R 777 /home/kali/Desktop/web
chmod -R 777 /home/kali/Desktop/binaries

cd /home/kali/Desktop 

echo "Relog to refresh group membership"                                                                                                                         

