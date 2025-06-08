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

$global:Passwords = @(
  "hjc090103", "98116290", "lorenzo31972", "boy150", "0839062821", "booyaa2", "OCTUBRE71959", "ls04040922!",
  "alejito419", "thomson82", "kh1995", "lilg787", "AMELIAJC", "384177", "fujiboris2", "*gammallama*", "gebs10",
  "jerry9501", "splash_05", "ronirodriguez", "slavelabor", "1174334522", "keonny19", "dav7dog2", "uzbk2062", "olea1",
  "lovemano", "0542340", "stonest", "0724034560", "tenisica1", "volvo440glt", "sexyv08", "2282989", "maritimo",
  "hp456hp", "Smash6600", "26119936", "544516419", "1912272", "Mercadez1403", "236545", "kill4cute", "kingsleigh",
  "hasanhanim", "snoopdogg-gunit", "coleyisnumber1", "esloyola", "tourelady1", "hookerbitch", "pala0281", "ff123456",
  "horses01", "Temp1234", "20swim00", "babybow", "mapele", "irukasensesi", "didimakimou", "snowcobunny7",
  "JUANITA_BABII", "tyan10", "123456rj", "cole5876", "maddara64", "erkkS", "nooairza", "bebo91",
  "elpier_333@hotmail.com", "cassise4e", "hetbokje", "PLUISJE2002", "0819726989", "8265571", "cazzialformaggio",
  "maletta", "fletcha08", "boyzinblu", "0403734122", "crazymono2", "kaboomz80", "yadicaco", "jjjj2970", "tealea20",
  "MILDEMONIOS", "bonn55", "mobile0429940788", "ctmnohk", "ABC1234", "0860006432", "798323569", "092943382",
  "SRILANKAN", "vth6966969vth", "crosbystreet", "FreddieG", "reptiles3", "dcorkie99", "predial", "mrk2398gt3",
  "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon",
  "123123", "abc123", "password1", "admin", "letmein", "welcome", "monkey", "login", "pass", "qwerty123",
  "starwars", "root", "shadow", "princess", "trustno1", "654321", "superman", "test", "zaq1zaq1", "batman",
  "master", "pass123", "hello", "freedom", "whatever", "asdfgh", "qazwsx", "admin123", "123321", "secret",
  "123qwe", "michael", "iloveyou", "123", "1q2w3e4r", "000000", "666666", "888888", "admin1", "login123"
)
$global:Usernames = @(
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

$global:Hostnames = @(
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

function Get-RandomAndRemove {
param (
    [Parameter(Mandatory)]
    [string]$ArrayName
  )

  # Get the global array
  $arrayRef = Get-Variable -Name $ArrayName -Scope Global -ErrorAction SilentlyContinue

  # Return $null if variable doesn't exist or has no elements
  if (-not $arrayRef -or -not $arrayRef.Value -or $arrayRef.Value.Count -eq 0) {
    return $null
  }

  $randIndex = Get-Random -Minimum 0 -Maximum $arrayRef.Value.Count
  $randomItem = $arrayRef.Value[$randIndex]

  # Remove the selected item
  $arrayRef.Value = $arrayRef.Value | Where-Object { $_ -ne $randomItem }

  # Update the global variable with modified array
  Set-Variable -Name $ArrayName -Value $arrayRef.Value -Scope Global

  return $randomItem
}



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
  rename-Computer "$DCName"

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
  Install-ADDSForest -DomainName $DomainName -DomainNetbiosName "LAB" -SafeModeAdministratorPassword (ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force) -InstallDNS -DomainNetbiosName $DomainNetbiosName

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
    (Get-Content C:\secpol.cfg) -replace 'PasswordComplexity\s*=\s*\d+', 'PasswordComplexity = 0' | Set-Content C:\secpol.cfg

    # Import the modified security policy
    secedit /configure /db secedit.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY

    # Clean up the temp file
    Remove-Item C:\secpol.cfg

    net accounts /minpwlen:1 /maxpwage:unlimited /minpwage:0 /uniquepw:1

  }

  Disable-PasswordComplexity
  Set-Password -username $DomainAdminUsername -newpassword $DomainAdminPassword
  function Add-RandomComputersToDomain {
  param(
      [string]$DomainName = $DomainName,
      [string]$OU = "OU=Workstations,DC=lab,DC=local",
      [string]$DomainUser = "lab\\Administrator",
      [string]$Password = "Administr@tor123"
    )

    # Convert password to SecureString
    $secPassword = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($DomainUser, $secPassword)

    for ($i = 1; $i -le 10; $i++) {
      # Generate random computer name (8 char max for legacy reasons)
      $compName = Get-RandomAndRemove -ArrayName Hostnames
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

  # Add rnadom users with weak password

  $group = [ADSI]"WinNT://./Users,group"
  for ($i = 1; $i -le 10; $i++) {
    try {
      $username = Get-RandomAndRemove -ArrayName Usernames
      $p = Get-RandomAndRemove -ArrayName Passwords
      $password = ConvertTo-SecureString $p -AsPlainText -Force
      New-LocalUser -Name $username -Password $password -FullName $username -Description "Guess the Password" -UserMayNotChangePassword -PasswordNeverExpires
      #Add-LocalGroupMember -Group "Users" -Member $username

      $group.Add("WinNT://./$username,user")
      Write-Host "[+] User '$username' created with password '$($user.password)'"
    }
    catch {
      Write-Host "[-] Failed to create user '$($user.name)': $_"
    }
  }

  Write-Host "[*] Creating users with description as password and no pre-auth..."



  foreach ($vu in $vulnUsers) {
    for ($i = 1; $i -le 5; $i++) {

      try {
        $u = Get-RandomAndRemove -ArrayName Usernames
        $p1 = Get-RandomAndRemove -ArrayName Passwords
        $p = ConvertTo-SecureString $p1 -AsPlainText -Force
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

  function Set-AdditionalUsers {
    # Example usage:
    $randomUser = Get-RandomAndRemove -ArrayName "usernames"
    Write-Host "Selected user: $randomUser"

    $randomPass = Get-RandomAndRemove -ArrayName "passwords"
    Write-Host "Selected pass: $randomPass"

    ## Disable LDAP Signing
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LDAPServerIntegrity' -Value 1
    Restart-Service ntds -Force

    # AS-REP Roastable User
    New-ADUser -Name "roastme" -SamAccountName "roastme" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -UserPrincipalName "roastme@lab.local" -Path "CN=Users,DC=lab,DC=local" -PassThru | Set-ADAccountControl -DoesNotRequirePreAuth $true

    ## Kerberoastable Service Account

    New-ADUser -Name "svc_backup" -SamAccountName "svc_backup" -UserPrincipalName "svc_backup@lab.local" -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) -ServicePrincipalNames "MSSQLSvc/DC01.lab.local:1433" -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,DC=lab,DC=local"

    ## User with Password in Description (Info Disclosure)

    New-ADUser -Name "jdoe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@lab.local" -AccountPassword (ConvertTo-SecureString "Welcome123" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -Description "Temp password is Welcome123" -Path "CN=Users,DC=lab,DC=local"

    ## Local Admin (Non-Domain Admin)

    New-ADUser -Name "adminlocal" -SamAccountName "adminlocal" -UserPrincipalName "adminlocal@lab.local" -AccountPassword (ConvertTo-SecureString "P@ssword" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,DC=lab,DC=local"
    Add-ADGroupMember -Identity "Administrators" -Members "adminlocal"

    ## High Priv User in a Custom Group (Priv Esc Opportunity)

    New-ADGroup -Name "PrivAppAdmins" -SamAccountName "PrivAppAdmins" -GroupScope Global -Path "CN=Users,DC=lab,DC=local"
    New-ADUser -Name "appadmin" -SamAccountName "appadmin" -UserPrincipalName "appadmin@lab.local" -AccountPassword (ConvertTo-SecureString "Qwerty123" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,DC=lab,DC=local"
    Add-ADGroupMember -Identity "PrivAppAdmins" -Members "appadmin"

    ## Privileged App Group with Escalation Potential

    New-ADGroup -Name "PrivAppAdmins" -SamAccountName "PrivAppAdmins" -GroupScope Global -Path "CN=Users,DC=lab,DC=local"
    New-ADUser -Name "appadmin" -SamAccountName "appadmin" -UserPrincipalName "appadmin@lab.local" -AccountPassword (ConvertTo-SecureString "Qwerty123" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,DC=lab,DC=local"
    Add-ADGroupMember -Identity "PrivAppAdmins" -Members "appadmin"

    ## Unconstrained Delegation (Lethal for Ticket Abuse)

    New-ADUser -Name "printsvc" -SamAccountName "printsvc" -UserPrincipalName "printsvc@lab.local" -AccountPassword (ConvertTo-SecureString "Spring2022" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,DC=lab,DC=local"
    Set-ADAccountControl -Identity "printsvc" -TrustedForDelegation $true

    ## Golden Ticket Bait: KRBTGT Reset + Weak Password Logging

    Set-ADAccountPassword -Identity "krbtgt" -NewPassword (ConvertTo-SecureString "Winter2020" -AsPlainText -Force) -Reset
    Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target "lab.local" -Confirm:$false -ErrorAction Stop

    ## User with WriteDACL Permission on a Group (ACL Privesc)

    New-ADUser -Name "acluser" -SamAccountName "acluser" -UserPrincipalName "acluser@lab.local" -AccountPassword (ConvertTo-SecureString "12345678" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -Path "CN=Users,DC=lab,DC=local"
    $group = Get-ADGroup -Identity "Domain Admins"
    $acl = Get-ACL "AD:$($group.DistinguishedName)"
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule("acluser", "WriteDacl", "Allow")
    $acl.AddAccessRule($rule)
    Set-ACL -ACLObject $acl "AD:$($group.DistinguishedName)"

    ## GPO Write Permissions for Low-Priv User

    Set-GPPermissions -Name "Default Domain Policy" -TargetName "appadmin" -TargetType User -PermissionLevel GpoEdit
  }
  function Set-SMBVersion {
    # Disable SMB Signing on client side
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuritySignature -Value 0

# Disable SMB Signing on server side
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RequireSecuritySignature -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name EnableSecuritySignature -Value 0
  }
  function Set-SMBSigning {
    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName FS-SMB1 -NoRestart
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    # Set-SmbServerConfiguration -EnableSMB2Protocol $false
    #Set-SmbServerConfiguration -EnableSMB2Protocol $true
  }
  function Set-NullAuth {
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 0
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 0
New-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionPipes' -PropertyType MultiString -Value @("lsarpc","samr","netlogon") -Force

    # Allow null sessions on IPC$
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -Value @("IPC$") -PropertyType MultiString -Force

# Loosen anonymous restrictions
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 0

    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" | Select-Object RestrictAnonymous, RestrictAnonymousSAM

    New-SmbShare -Name "test" -Path "C:\Users\Public" -FullAccess Everyone
    Set-SmbShare -Name "test" -FolderEnumerationMode AccessBased -Force
Set-SmbShare -Name "test" -CachingMode None - Force

  Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
    Set-SmbServerConfiguration -EnableInsecureGuestLogons $true -Force

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionPipes" -PropertyType MultiString -Value @("lsarpc", "samr", "netlogon") -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "NullSessionShares" -PropertyType MultiString -Value @("IPC$") -Force
  }
  # Add Vulnerabilities
  Add-GoldenTicketVuln
  Add-SilverTicketVuln
  Add-UnconstrainedDelegationVuln
  Add-GroupMembershipVuln
  Add-AdminSDHolderVuln
  Add-WMIDCOMVuln
  Set-AdditionalUsers
  Set-NullAuth
  Set-SMBVersion
  Set-SMBSigning
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
  else {
    Add-ADVulnerabilities
  }


}

# Run setup
Setup-Environment

Write-Host "[*] Active Directory setup and vulnerabilities have been successfully configured!"
