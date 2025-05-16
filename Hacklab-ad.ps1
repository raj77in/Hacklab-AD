# PowerShell Script for AD Setup and Vulnerabilities with Exploitation Hints

# Set the domain name for the environment
$DomainName = "lab.local"
$DomainNetbiosName = "LAB"
$DomainAdminUsername = "Administrator"
$DomainAdminPassword = "Adminstr@tor123" # Use a secure password
$DCName = "Server2025"

# Amit Agarwal aka - 2025-05-10
# Script to configure static IP on Windows Server

$InterfaceAlias = "Ethernet0"       # Or "Ethernet0", run Get-NetAdapter if unsure
$IPAddress = "172.16.70.10"
$PrefixLength = 24               # For 255.255.255.0
$DefaultGateway = "172.16.70.1"
$DNSServers = "172.16.70.10", "192.168.110.1"


function Set-IPandName {

  # Set Static IP

  # Check if the IP already exists
  $existing = Get-NetIPAddress -IPAddress $IPAddress -ErrorAction SilentlyContinue

  if ($existing) {
    # Remove existing IP if it's already set
    $existing | Remove-NetIPAddress -Confirm:$false
  }



  # Step 2: Remove DHCP if it's enabled
  $adapter = Get-NetIPInterface -InterfaceAlias $InterfaceAlias -AddressFamily IPv4
  if ($adapter.Dhcp -eq "Enabled") {
    Set-NetIPInterface -InterfaceAlias $InterfaceAlias -Dhcp Disabled
  }

  # Step 3: Set Static IP
  New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $IPAddress -PrefixLength $PrefixLength -DefaultGateway $DefaultGateway

  # Step 4: Set DNS Servers
  Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DNSServers
  rename-Computer DC01

}

function Set-Password {
param(
    [string]$username,
    [string]$newpassword
  )

  $user = [ADSI]"WinNT://./$username,user"
  $user.SetPassword( $newpassword)
}




# Function to Install Active Directory and promote DC
function Install-ActiveDirectory {
  Write-Host "[*] Installing Active Directory..."

  Set-Password -username 'Administrator' -newpassword 'Amitag123$'

  # Install the AD DS role
  Install-WindowsFeature -Name AD-Domain-Services

  # Create the new forest and domain
  Install-ADDSForest -DomainName $DomainName -DomainNetbiosName "LAB" -SafeModeAdministratorPassword (ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force) -InstallDNS

  Get-WindowsFeature RSAT-AD-Tools
  Install-WindowsFeature RSAT-AD-Tools

  Write-Host "[*] Active Directory installed and Domain Controller promoted!"
}


# Function to Add Vulnerabilities to Active Directory
function Add-ADVulnerabilities {
  Write-Host "[*] Adding Active Directory Vulnerabilities..."


  Function Disable-PasswordComplexity {
    Write-Host "[*] Checking and disabling password complexity if needed..."

    $cfgFile = "$env:TEMP\secpol.cfg"

    secedit /export /cfg $cfgFile | Out-Null

    $cfg = Get-Content $cfgFile
    if ($cfg -match 'PasswordComplexity\s*=\s*1') {
      $cfg = $cfg -replace 'PasswordComplexity\s*=\s*1', 'PasswordComplexity = 0'
      $cfg | Set-Content $cfgFile

      secedit /configure /db "$env:windir\Security\Database\secedit.sdb" /cfg $cfgFile /areas SECURITYPOLICY | Out-Null

      Write-Host "[+] Password complexity disabled. Updating group policy..."
      gpupdate /force | Out-Null
      Start-Sleep -Seconds 2
    }
    else {
      Write-Host "[=] Password complexity already disabled."
    }

    Remove-Item $cfgFile -Force -ErrorAction SilentlyContinue


    # Set the local security policy to disable password complexity
    secedit /export /cfg C:\secpol.cfg

    # Replace the relevant line (or add it if missing)
    (gc C:\secpol.cfg) -replace 'PasswordComplexity\s*=\s*\d+', 'PasswordComplexity = 0' | Set-Content C:\secpol.cfg

    # Import the modified security policy
    secedit /configure /db secedit.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY

    # Clean up the temp file
    Remove-Item C:\secpol.cfg

    net accounts /minpwlen:1 /maxpwage:unlimited /minpwage:0 /uniquepw:1

  }

  Disable-PasswordComplexity
  Set-Password -username "Administrator" -newpassword $DomainAdminPassword
  function Add-RandomComputersToDomain {
  param(
      [string]$DomainName = "lab.local",
      [string]$OU = "OU=Workstations,DC=lab,DC=local",
      [string]$DomainUser = "lab\\Administrator",
      [string]$Password = "Administr@tor123"
    )

    # Convert password to SecureString
    $secPassword = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($DomainUser, $secPassword)

    for ($i = 1; $i -le 5; $i++) {
      # Generate random computer name (8 char max for legacy reasons)
      $compName = "PC-" + -join ((65..90) + (48..57) | Get-Random -Count 6 | % { [char]$_ })
      Write-Host "`n[+] Creating computer: $compName"

      try {
        New-ADComputer -Name $compName `
        -SamAccountName $compName$ `
        -Enabled $true

        Write-Host "[+] Added $compName to domain in OU: $OU" -ForegroundColor Green
      }
      catch {
        Write-Warning "[-] Failed to add $compName : $_"
      }
    }
  }

  Add-RandomComputersToDomain
  Write-Host "[*] Creating 3 local users with weak passwords..."

  $users = @(
    @{name = 'guest1'; password = 'guest' },
    @{name = 'testuser'; password = 'test' },
    @{name = 'user1'; password = 'password' },
    @{name = '123user'; password = '123' }
  )

  $group = [ADSI]"WinNT://./Users,group"
  foreach ($user in $users) {
    try {
      $username = $user.name
      $password = ConvertTo-SecureString $user.password -AsPlainText -Force
      New-LocalUser -Name $username -Password $password -FullName $username -Description "Password is $($user.password)" -UserMayNotChangePassword -PasswordNeverExpires
      #Add-LocalGroupMember -Group "Users" -Member $username

      $group.Add("WinNT://./$username,user")
      Write-Host "[+] User '$username' created with password '$($user.password)'"
    }
    catch {
      Write-Host "[-] Failed to create user '$($user.name)': $_"
    }
  }

  Write-Host "[*] Creating users with description as password and no pre-auth..."

  $vulnUsers = @(
    @{name = 'descpw'; password = 'Descpw@123' },
    @{name = 'nopreauth'; password = 'Nopreauth@123' },
    @{name = 'weakpwd'; password = 'Passw0rd!' }
  )

  foreach ($vu in $vulnUsers) {
    try {
      $u = $vu.name
      $p = ConvertTo-SecureString $vu.password -AsPlainText -Force
      $user = New-LocalUser -Name $u -Password $p -FullName $u -Description "Password is $($vu.password)" -UserMayNotChangePassword -PasswordNeverExpires

      if ($user) {
        #Add-LocalGroupMember -Group "Users" -Member $u
        $group.Add("WinNT://./$u,user")
        Write-Host "[+] Vuln user '$u' created with password '$($vu.password)'."
      }
    }
    catch {
      Write-Host "[-] Error creating vuln user '$($vu.name)': $_"
    }
  }

  Write-Host "[*] Creating auto-login user..."

  $autoUser = "autologin"
  $autoPass = "autologin"
  try {
    $securePass = ConvertTo-SecureString $autoPass -AsPlainText -Force
    New-LocalUser -Name $autoUser -Password $securePass -FullName $autoUser -Description "Auto-login user" -UserMayNotChangePassword -PasswordNeverExpires
    #Add-LocalGroupMember -Group "Administrators" -Member $autoUser
    $group = [ADSI]"WinNT://./Administrators,group"
    $group.Add("WinNT://./$autoUser,user")

    Write-Host "[+] Auto-login user created."

    Write-Host "[*] Enabling auto-login for '$autoUser'..."
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1" -Type String
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUsername" -Value $autoUser -Type String
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $autoPass -Type String
  }
  catch {
    Write-Host "[-] Failed to create autologin user: $_"
  }

  Write-Host "[*] Delegation setup (Unconstrained) for autologin user..."
  try {
    $deleg = Get-ADUser -Identity $autoUser
    if ($deleg) {
      Set-ADAccountControl -Identity $autoUser -TrustedForDelegation $true
      Write-Host "[+] Delegation enabled for $autoUser"
    }
    else {
      Write-Host "[-] Auto-login user not found in AD. Delegation skipped."
    }
  }
  catch {
    Write-Host "[-] Delegation setup failed or not in domain: $_"
  }

  Write-Host "[*] Enabling RDP..."
  try {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" | Out-Null
    Write-Host "[+] RDP enabled and firewall rule allowed."
  }
  catch {
    Write-Host "[-] Failed to enable RDP: $_"
  }

  # Import Active Directory module if not already available
  Import-Module ActiveDirectory

  # Create an organizational unit (OU) for users
  #New-ADOrganizationalUnit -Name "Users" -Path "DC=lab,DC=local"

  # Create a sample user (user1)
  # New-ADUser -SamAccountName "user1" -UserPrincipalName "user1@lab.local" `
  # -Name "User One" -GivenName "User" -Surname "One" `
  # -AccountPassword (ConvertTo-SecureString -String "P@ssw0rd123" -AsPlainText -Force) `
  # -Enabled $true -PassThru

  # Add user1 to the Domain Admins group
  Add-ADGroupMember -Identity "Domain Admins" -Members "user1"

  # Enable Unconstrained Delegation for user1 (potential attack vector)
  Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0

  Set-ADUser -Identity "user1" -TrustedForDelegation $true

  # Enable SID History Injection (Simulate with dummy user)
  # Set-ADUser -Identity "user1" -Add @{SIDHistory = "S-1-5-32-544" }

  # Set up RDP for the Domain Admin user
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
  -Name "fDenyTSConnections" -Value 0
  Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

  # Enable autoruns for post-exploitation
  Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "MaliciousTool" -Value "C:\path\to\tool.exe"

  # Allow inbound RDP connections
  New-NetFirewallRule -DisplayName "Allow RDP" `
  -Direction Inbound -Protocol TCP `
  -LocalPort 3389 -Action Allow

  # Dump the credentials (Simulated here for demonstration)
  # Note: In real-world testing, use proper tools like Mimikatz for credential dumping.
  Write-Host "Simulating credential dump..."
  Get-ADUser -Filter * -Properties * | Select-Object SamAccountName, UserPrincipalName, Enabled

  # Finish
  Write-Host "Domain setup complete with user and post-exploitation setup."


  # Golden Ticket Vulnerability (Kerberos Ticket Abuse)
  function Add-GoldenTicketVuln {
    Write-Host "[*] Adding Golden Ticket vulnerability"
    # Placeholder for Kerberos ticket abuse vulnerability
    Write-Host "[*] Hint: Use Mimikatz to dump krbtgt hash and create a Golden Ticket."
  }

  # Silver Ticket Vulnerability (Ticket Granting Service)
  function Add-SilverTicketVuln {
    Write-Host "[*] Adding Silver Ticket vulnerability"
    # Placeholder for Silver Ticket creation
    Write-Host "[*] Hint: Use Mimikatz to create Silver Tickets using the service account hash."
  }

  # Unconstrained Delegation vulnerability
  function Add-UnconstrainedDelegationVuln {
    Write-Host "[*] Adding Unconstrained Delegation vulnerability"
    # Enable Unconstrained Delegation for a user
    Set-ADUser -Identity "user1" -TrustedForDelegation $true
    Write-Host "[*] Unconstrained Delegation enabled for user1."
    Write-Host "[*] Hint: This allows the user to impersonate any other user on the network."
  }

  # Group Membership Misconfiguration (e.g., Domain Admins)
  function Add-GroupMembershipVuln {
    Write-Host "[*] Adding Group Membership misconfiguration"
    $group = Get-ADGroupMember -Identity "Domain Admins"
    if ($group -notcontains "user1") {
      Add-ADGroupMember -Identity "Domain Admins" -Members "user1"
      Write-Host "[*] user1 added to Domain Admins."
    }
    else {
      Write-Host "[*] user1 is already a member of Domain Admins."
    }
    Write-Host "[*] Hint: Adding a non-admin user to the Domain Admins group escalates their privileges."
  }

  # AdminSDHolder Misconfiguration
  function Add-AdminSDHolderVuln {
    Write-Host "[*] Adding AdminSDHolder misconfiguration"
    $insecureAcl = Get-Acl -Path "AD:\CN=AdminSDHolder,CN=System,DC=lab,DC=local"
    if ($insecureAcl.Access | Where-Object { $_.AccessControlType -eq "Allow" }) {
      Write-Host "[*] AdminSDHolder already has insecure ACL."
    }
    else {
      Set-ACL -Path "AD:\CN=AdminSDHolder,CN=System,DC=domain,DC=com" -AclObject $insecureAcl
      Write-Host "[*] Insecure ACL applied to AdminSDHolder."
    }
    Write-Host "[*] Hint: Misconfigured AdminSDHolder can lead to privilege escalation."
  }

  # SID History Injection vulnerability
  function Add-SIDHistoryVuln {
    Write-Host "[*] Adding SID History Injection vulnerability"
    $user = Get-ADUser -Identity "user1" -Properties SIDHistory
    if ($user.SIDHistory -notcontains "S-1-5-32-544") {
      Set-ADUser -Identity "user1" -Add @{SIDHistory = "S-1-5-32-544" } # Domain Admin SID
      Write-Host "[*] SID History injected with Domain Admin SID."
    }
    else {
      Write-Host "[*] SID History already contains Domain Admin SID."
    }
    Write-Host "[*] Hint: SID History allows an attacker to inject domain admin SID into their account for privilege escalation."
  }

  # Enable WMI/DCOM Remoting vulnerability
  function Add-WMIDCOMVuln {
    Write-Host "[*] Enabling WMI/DCOM Remoting"
    if (-not (Get-Service -Name Winmgmt).Status -eq 'Running') {
      Enable-WmiService
      Write-Host "[*] WMI/DCOM Remoting enabled."
    }
    else {
      Write-Host "[*] WMI/DCOM Remoting is already enabled."
    }
    Write-Host "[*] Hint: WMI/DCOM can be abused for remote code execution on compromised machines."
  }

  # Add Vulnerabilities
  Add-GoldenTicketVuln
  Add-SilverTicketVuln
  Add-UnconstrainedDelegationVuln
  Add-GroupMembershipVuln
  Add-AdminSDHolderVuln
  Add-WMIDCOMVuln
}

# Create the AD domain and install vulnerabilities
function Setup-Environment {
  $touchFile = "$env:USERPROFILE\rename_done.flag"
  $touchFile2 = "$env:USERPROFILE\ADInstalled_done.flag"

  if (-Not (Test-Path $touchFile)) {
    Set-IPandName
    New-Item -Path $touchFile -ItemType File -Force | Out-Null
    Write-Host "[i] Touch file created: $touchFile"
    Restart-Computer
  }
  elseif (-Not (Test-Path $touchFile2)) {
    Install-ActiveDirectory

    New-Item -Path $touchFile2 -ItemType File -Force | Out-Null
    Write-Host "[i] Touch file created: $touchFile2"
    Restart-Computer
  }
  else{
    Add-ADVulnerabilities
  }


}

# Run setup
Setup-Environment

Write-Host "[*] Active Directory setup and vulnerabilities have been successfully configured!"
