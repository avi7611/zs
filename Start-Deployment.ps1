#-----------------------------------------------------------------------------------------------#
#   These are the underlying helper functions. DO NOT CHANGE THIS CODE.
#-----------------------------------------------------------------------------------------------#
$Script:Computers = @()
$Script:Users = @()
$Script:RemovedComputers = @()
$Script:RemovedUsers = @()
$Script:UserAuditGUIDS = @{}
$Script:CompAuditGUIDS = @{}

## To ensure that we do not get a mismatched TLS version on the API request
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

function Test-DecoyComputer {
    [CmdletBinding()]
    Param(
        [String]
        $Computer
    )
    
    Process {
        try {
            if( @(Get-ADComputer -Identity $Computer).Count) {
                return $true
            }
        }
        catch {
            return $false
        }
    }
}

function Test-DecoyUser{
    [CmdletBinding()]
    Param(
        [String]
        $Username
    )

    Process {
        try {
            if( @(Get-ADUser -Identity $Username).Count) {
                return $True
            }
        }
        catch {
            return $False
        }
    }
}

function Test-OU {
    [CmdletBinding()]
    Param (
        [String]
        $OUDistinguishedName
    )

    Process {
        if( @(Get-ADOrganizationalUnit -Identity $OUDistinguishedName).Count ) {
            return $True
        }
        else {
            return $False
        }
    }
}

function Test-Group {
    [CmdletBinding()]
    Param (
        [String]
        $GroupName
    )
    Process {
        try {
            if( @(Get-ADGroup -Identity $GroupName).Count) {
                return $True
            }
        }
        catch {
            return $False
        }
    }
}

function Move-DecoyObjectToOU {
    [CmdletBinding()]
    Param(
        [String]
        $DecoyGUID,

        [String]
        $OU,

        [String]
        $ObjectType
    )
    
    Process {
        # 
        # Checking if the specified OU exists
        #
        Write-Output "[+] Checking if Organizational Unit [$OU] exists..."
        if (!(Test-OU -OUDistinguishedName $OU)) {
            Write-Output "[-] OU [$OU] does not exist. Exiting..."
            return
        }

        # 
        # All things look good. Moving to OU
        #
        Write-Output "[+] Moving to OU [$OU]"
        Move-ADObject -Identity $DecoyGUID -TargetPath $OU

        Write-Output "[+] Done."
    }
}

function New-DecoyUserPassword {
    [CmdletBinding()]
    Param (
        [Int]
        $Length
    )

    Process {
        $pass = ( -join ( (0x23..0x2D) + (0x40) + (0x30..0x39) + ( 0x41..0x5A) + ( 0x61..0x7A) | Get-Random -Count $length  | % {[char]$_}) )
        return $pass
    }
}

function Add-DecoyUserToGroup {
    [CmdletBinding()]
    Param (
        [String]
        $Username,

        [String]
        $Groupname
    )

    Process {
        if (!(Test-Group -Groupname $Groupname)) {
            Write-Output "[!] Group [$Groupname] does not exist. Exiting..."
            return
        }
        else {
            Write-Output "[+] Moving User [$Username] to Group [$Groupname]"
            Add-ADGroupMember -Identity $GroupName -Members $Username
        }
    }
}

function Remove-DecoyUserFromGroup {
    [CmdletBinding()]
    Param (
        [String]
        $Username,

        [String]
        $Groupname
    )

    Process {
        if (!(Test-Group -Groupname $GroupName)) {
            Write-Output "[!] Group [$Groupname] does not exist. Exiting..."
            return
        }
        else {
            Write-Output "[+] Removing user [$Username] from Group [$GroupName]"
            Remove-ADGroupMember -Identity $GroupName -Members $Username -Confirm:$False
        }
    }
}

function Get-GUIDFromSchemaAttribute {
    [CmdletBinding()]
    Param (
        [String]
        $Attribute
    )

    Process {
        $SearchFilter = @{
            SearchBase = (Get-ADRootDSE).schemaNamingContext
            Filter = "Name -eq '$Attribute' -And objectclass -eq 'attributeSchema'"
            Properties = 'schemaIDGUID'
        }

        $Result = Get-ADObject @SearchFilter

        if ($Result) {
            $AttrGUID = $Result.SchemaIDGUID -As [GUID] 
            return $AttrGUID
        }
    }
}

function Resolve-AttributeGuids {
    [CmdletBinding()]
    Param (
        [String[]]
        $UserAuditAttributes,

        [String[]]
        $ComputerAuditAttributes
    )

    Process {
        Write-Output "[*] Resolving user attribute GUIDS..."
        foreach ($Attr in $UserAuditAttributes) {
            if($Script:UserAuditGUIDS.ContainsKey($Attr)) { continue }
            $Value = Get-GUIDFromSchemaAttribute -Attribute $Attr
            $Script:UserAuditGUIDS.Add($Attr, $Value)
        }

        Write-Output "[*] Resolving computer attribute GUIDS..."
        foreach ($Attr in $ComputerAuditAttributes) {
            if($Script:CompAuditGUIDS.ContainsKey($Attr)) { continue }
            $Value = Get-GUIDFromSchemaAttribute -Attribute $Attr
            $Script:CompAuditGUIDS.Add($Attr, $Value)
        }
    }
}

function Enable-Auditing {
    [CmdletBinding()]
    Param(
      [Parameter(Position = 0, Mandatory = $True)]
      [String]
      $objectDN,

      [Parameter(Position = 1, Mandatory = $True)]
      [String]
      [ValidateSet ("User","Computer")]
      $ObjectType,

      [Parameter(Position = 2, Mandatory = $False)]
      [String]
      [ValidateSet ("Success","Failure")]
      $AuditFlag="Success",

      [Parameter(Position = 3, Mandatory = $False)]
      [String]
      [ValidateSet ("GenericAll","GenericRead","GenericWrite","ReadControl","ReadProperty","WriteDacl","WriteOwner","WriteProperty")]
      $AuditRight = "ReadProperty",

      [Parameter(Position = 4, Mandatory = $False)]
      [Bool]
      [ValidateSet ($True,$False)]
      $RemoveAudit=$False
    )
    
    Process {
        $ACL = Get-Acl -Path "AD:\$ObjectDN"
        if ($ACL -eq $null) {
            Write-Output "[!] No ACL found [$ObjectDN]."
            return
        }
        $Principal = "Everyone"
        $sid = New-Object System.Security.Principal.NTAccount($Principal)
        
        switch ($ObjectType) {
            "User" {
                if (!$RemoveAudit) {
                    foreach ($UserGuid in $UserAuditGUIDS.Keys) {
                        $targetGUID = $UserAuditGUIDS[$UserGuid] -As [GUID]
                        Write-Output "[+] Enabling detection on attribute [$UserGuid] for GUID $targetGUID"
                        $AuditRule = New-Object DirectoryServices.ActiveDirectoryAuditRule($sid, $AuditRight, $AuditFlag, $targetGUID)
                        $ACL.AddAuditRule($AuditRule)
                    }
                }
                elseif ($RemoveAudit) {
                    foreach ($UserGuid in $UserAuditGUIDS.Keys) {
                        $targetGUID = $UserAuditGUIDS[$UserGuid] -As [GUID]
                        Write-Output "[+] Disabling detection on attribute [$UserGuid] for GUID [$targetGUID]"
                        $AuditRule = New-Object DirectoryServices.ActiveDirectoryAuditRule($sid, $AuditRight, $AuditFlag, $targetGUID)
                        $ACL.RemoveAuditRule($AuditRule)
                    }
                }
            }

            "Computer" {
                if (!$RemoveAudit) {
                    foreach ($CompGuid in $CompAuditGUIDS.Keys) {
                        $targetGUID = $CompAuditGUIDS[$CompGuid] -As [GUID]
                        Write-Output "[+] Enabling detection on attribute [$CompGuid] for GUID [$targetGUID]"
                        $AuditRule = New-Object DirectoryServices.ActiveDirectoryAuditRule($sid, $AuditRight, $AuditFlag, $targetGUID)
                        $ACL.AddAuditRule($AuditRule)
                    }
                }
                elseif ($RemoveAudit) {
                    foreach ($CompGuid in $CompAuditGUIDS.Keys) {
                        $targetGUID = $CompAuditGUIDS[$CompGuid] -As [GUID]
                        Write-Output "[+] Disabling detection on attribute [$CompGuid] for GUID [$targetGUID]"
                        $AuditRule = New-Object DirectoryServices.ActiveDirectoryAuditRule($sid, $AuditRight, $AuditFlag, $targetGUID)
                        $ACL.RemoveAuditRule($AuditRule)
                    }
                }

            }
        }

        Write-Output "[+] Setting ACL..."
        Set-ACL "AD:\$ObjectDN" -AclObject $ACL
    }
}

function Enable-ADEnumDetection {
    Param (
        [String]
        $ObjectName,

        [String]
        [ValidateSet ("User","Computer")]
        $ObjectType,

        [Bool]
        $RemoveAudit=$False
    )

    Process {
        if ($ObjectType -eq "User") {
            Write-Output "[+] Enabling detection for user [$ObjectName]"
            $UserDN = (Get-ADUser -Identity $ObjectName).DistinguishedName
            Enable-Auditing -ObjectDN $UserDN -ObjectType $ObjectType -RemoveAudit $RemoveAudit
            Write-Output "[+] Done! [$ObjectName]"

        }

        elseif ($ObjectType -eq "Computer") {
            Write-Output "[+] Enabling detection for computer [$ObjectName]"
            $CompDN = (Get-ADComputer -Identity $ObjectName).DistinguishedName
            Enable-Auditing -ObjectDN $CompDN -ObjectType $ObjectType -RemoveAudit $RemoveAudit
            Write-Output "[+] Done! [$ObjectName]"
        }
    }
}

function Remove-DecoyUser {
    [CmdletBinding()]
    param (
        [String]
        $Username,

        [Boolean]
        $Deployed
    )
    
    process {
        Write-Host "[+] Removing User [$Username]"
        if(Test-DecoyUser -Username $Username) {
            Remove-ADUser -Identity $Username -Confirm:$False
            if(!$Deployed) {
                $Script:RemovedUsers += $Username
            }
        }
        else {
            Write-Host "[!] User [$Username] not found."
        }
    }
}

function Remove-DecoyComputer {
    [CmdletBinding()]
    param (
        [String]
        $ComputerName,

        [Boolean]
        $Deployed
    )
    
    process {
        Write-Host "[+] Removing Computer [$Computername]"
        if(Test-DecoyComputer -Computer $ComputerName) {
            Remove-ADComputer -Identity $ComputerName -Confirm:$False
            if(!$Deployed) {
                $Script:RemovedComputers += $ComputerName
            }
        }
        else {
            Write-Host "[!] Computer [$ComputerName] not found."
        }
    }
}

function Test-DCAuditPolicies {
    [CmdletBinding()]
    param ()

    process {
        $TempFileName = "$($env:TEMP)\rsop.xml"
        $AuditPolicies = @(
            "Audit Logon",
            "Audit Kerberos Authentication Service",
            "Audit Directory Service Access",
            "Audit Kerberos Service Ticket Operations"
        )
        $DomainControllers = Get-ADDomainController -Filter *
        foreach($DomainController in $DomainControllers) {
            $AuditPolicyStatus = @{}
            foreach($Policy in $AuditPolicies) { $AuditPolicyStatus[$Policy] = $False }
            Write-Output "[+] Testing Audit Policies for $($DomainController.Name)"
            Get-GPResultantSetOfPolicy -Computer $DomainController.Name -Path $TempFileName -ReportType Xml | Out-Null
            [xml]$Rsop = Get-Content -Path $TempFileName
            $ExtensionData = $Rsop.Rsop.ComputerResults.ExtensionData
            foreach($Data in $ExtensionData) {
                if($Data.Extension.AuditSetting.Length -eq 0) {
                    break
                }
                $AuditSettings = $Data.Extension.AuditSetting
                foreach($Setting in $AuditSettings) {
                    foreach($AuditPolicy in $AuditPolicies) {
                        if($Setting.SubCategoryName -eq $AuditPolicy) { $AuditPolicyStatus[$AuditPolicy] = $True }
                    }
                }
            }

            foreach($Status in $AuditPolicyStatus.GetEnumerator()) {
                if ($Status.Value -eq $False) { 
                    Write-Host -ForegroundColor Red "[!] [$($Status.Name)] not enabled on [$DomainController]."
                }
                else {
                    Write-Host -ForegroundColor Green "[!] [$($Status.Name)] enabled on [$DomainController]."
                }
            }
            Remove-Item -Path $TempFileName
        }
    }
}

function Test-DecoyUserDeployment {
    [CmdletBinding()]
    param (
        [String]
        $Username,

        [String]
        $SPN,

        [Boolean]
        $ASREPRoastable,

        [String]
        $LogonWkst,

        [String]
        $Domain,

        [String]
        $ProfilePath,

        [String]
        $Description,

        [String]
        $GroupName,

        [Boolean]
        $PasswordNeverExpires,
    
        [String]
        $OU,

        [String]
        $FirstName,

        [String]
        $LastName,

        [String]
        $TelephoneNumber,

        [String]
        $Email
    )
    process {
        Write-Output "[+] Checking deployment for user [$Username]"
        if (!(Test-DecoyUser -Username $Username)) {
            Write-Host "[!] User [$Username] does not exist! Failed to verify. Skipping..."
            return
        }
        $User = Get-ADUser -Identity $Username -Properties *
        $Valid = $True
        
        $ASREPRoastMask = 0x400000
        $PasswordNeverExpireMask = 0x10000
        
        if ((($User.useraccountcontrol -band $ASREPRoastMask) -ne 0) -ne $ASREPRoastable) {
            $Valid = $False
            Write-Host "[!] ASREPRoasting incorrect, expected setting to be [$ASREPRoastable]" -ForegroundColor Red
        }

        if ((($User.useraccountcontrol -band $PasswordNeverExpireMask) -ne 0) -ne $PasswordNeverExpires) {
            $Valid = $False
            Write-Host "[!] PasswordNeverExpire incorrect, expected setting to be [$PasswordNeverExpires]" -ForegroundColor Red
        }

        if ($ProfilePath) {
            if ($User.ProfilePath -ne $ProfilePath) {
                $Valid = $False
                Write-Host "[!] Profile path is incorrect, expected [$ProfilePath]" -ForegroundColor Red
            }
        }

        if ($Description) {
            if ($User.Description -ne $Description) {
                $Valid = $False
                Write-Host "[!] Description is incorrect, expected [$Description]" -ForegroundColor Red
            }
        }

        if ($LogonWkst) {
            if ($User.Logonworkstations -ne $LogonWkst) {
                $Valid = $False
                Write-Host "[!] Logonworkstations is incorrect, expected [$LogonWkst]" -ForegroundColor Red
            }
        }

        if ($FirstName) {
            if ($User.firstname -ne $FirstName) {
                $Valid = $False
                Write-Host "[!] Firstname is incorrect, expected [$Firstname]" -ForegroundColor Red
            }
        }

        if ($LastName) {
            if ($User.Lastname -ne $LastName) {
                $Valid = $False
                Write-Host "[!] Last name is incorrect, expected [$LastName]" -ForegroundColor Red
            }
        }

        if ($OU) {
            if (@(Get-ADUser -SearchBase $OU -Filter "Name -eq '$Username'").Count -eq 0) {
                $Valid = $False
                Write-Host "[!] User not present in OU [$OU]" -ForegroundColor Red
            }
        }

        if ($TelephoneNumber) {
            if ($User.OfficePhone -ne $TelephoneNumber) {
                $Valid = $False
                Write-Host "[!] User does not have the right Office phone number, expected [$TelephoneNumber]"
            }
        }

        if ($Email) {
            if ($User.email -ne $Email) {
                $Valid = $False
                Write-Host "[!] User does not have the right email, expected [$Email]"
            }
        }

        if ($SPN) {
            $SPNs = $SPN.split(",")
            foreach($name in $SPNs) {
                if($User.ServicePrincipalNames -cnotcontains $name) {
                    $Valid = $False 
                    Write-Host "[!] SPN [$name] not present" -ForegroundColor Red
                }
            }
        }

        $Groups = $GroupName.split(",")
        if ($Groups) {
            foreach($Group in $Groups) {
                $Members = Get-ADGroupMember -Identity $Group | Select name, objectclass
                foreach($Member in $Members) {
                    if($Member.objectclass -ne "user") {
                        if ($Member.name -ne $Username) {
                            $Valid = $False
                            Write-Host "[!] User not present in group [$Group]"
                        }
                        else {
                            $Valid = $True
                        }
                    }
                }
            }
        }

        if(!$Valid) {
            Write-Host "[!] Failed verification of deployment for user [$Username]" -ForegroundColor Red
        }
        else {
            Write-Host "[!] Successfully verified deployment of [$Username]" -ForegroundColor Green
        }
    }
}

function Test-DecoyComputerDeployment {
    [CmdletBinding()]
    param (
        [String]
        $ComputerName,

        [String]
        $IPAddress,

        [String]
        $OSName,

        [String]
        $OSVersion,

        [String]
        $Servicepack,

        [String]
        $Domain,

        [String]
        $Description,

        [String]
        $OU
    )
    
    process {
        Write-Host "[+] Checking deployment configuration for [$ComputerName]"
        if(!(Test-DecoyComputer -Computer $ComputerName)) {
            Write-Host "[!] Computer object [$ComputerName] does not exist. Failed to verify. Skipping..." -ForegroundColor Red
            return
        }

        $Valid = $True
        try {
            $Answer = Resolve-DNSName -Name $ComputerName -Type A -ErrorAction stop 
            if($Answer.IPAddress -ne $IPAddress) {
                $Valid = $False
                Write-Host "[!] IP Address not configured in DNS correctly." -ForegroundColor Red
            }
        }
        catch {
            $Valid = $False
            Write-Host "[!] DNS A Record not configured for decoy" -ForegroundColor Red
        }

        $Computer = Get-ADComputer -Identity $ComputerName -Properties *

        if ($OSName) {
            if ($Computer.OperatingSystem -ne $OSName) {
                $Valid = $False
                Write-Host "[!] Incorrect OS name, expected [$OSName] found [$($Computer.OperatingSystem)]" -ForegroundColor Red
            }
        }

        if ($OSVersion) {
            if ($Computer.operatingsystemversion -ne $OSVersion) {
                $Valid = $False
                Write-Host "[!] Incorrect OS Version, expected [$OSVersion] found [$($Computer.OperatingSystemVersion)]" -ForegroundColor Red
            }
        }

        if ($Servicepack) {
            if ($Computer.operatingsytemservicepack -ne $Servicepack) {
                $Valid = $False
                Write-Host "[!] Incorrect OS Service Pack, expected [$Servicepack] found [$($Computer.operatignsystemservicepack)]" -ForegroundColor Red
            }
        }

        if ($Description) {
            if ($Computer.description -ne $Description) {
                $Valid = $False
                Write-Host "[!] Incorrect description, expected [$Description] found [$($Computer.description)]" -ForegroundColor Red
            }
        }

        if($OU) {
            if (@(Get-ADComputer -SearchBase $OU -Filter "Name -eq `"$ComputerName`"").Count -eq 0) {
                $Valid = $False
                Write-Host "[!] Computer not in OU [$OU], found in [$($Computer.distinguishedname)]" -ForegroundColor Red
            }
        }

        if (!$Valid) {
            Write-Host "[!] Verification failed for [$ComputerName]" -ForegroundColor Red
        }  
        else {
            Write-Host "[+] Successfully verified deployment for computer [$ComputerName]" -ForegroundColor Green
        }
    }
}

function Add-DecoyUser {
    [CmdletBinding()]
    param (
        [String]
        $Username,

        [String]
        $SPN,

        [Boolean]
        $ASREPRoastable,

        [String]
        $LogonWkst,

        [String]
        $Domain,

        [String]
        $ProfilePath,

        [String]
        $Description,

        [String]
        $GroupName,

        [Boolean]
        $PasswordNeverExpires,
    
        [String]
        $OU,

        [String]
        $FirstName,

        [String]
        $LastName,

        [String]
        $TelephoneNumber,

        [String]
        $Email,

        [Boolean]
        $EnableEnumDetection
    )
    
    process {
        Write-Host "[*] Checking if user [$Username] already exists"
        
        $length = 30
        Write-Output "[+] Generating random password of length [$length]"
        $plainpass = New-DecoyUserPassword -Length $length
        $securepass = ConvertTo-SecureString $plainpass -AsPlainText -Force

        # Check if user exists else add the user
        if (!(Test-DecoyUser -Username $Username)) { 
            Write-Output "[*] User Object [$Username] not found. Creating a new user..."
            Write-Output "[+] Adding the user [$Username]"
            New-ADuser $Username
        }
        else { 
            $Choice = Read-Host -Prompt "[!] User [$Username] already exists. Overwrite properties [Y/N]?"
            if (($Choice -ne "Y") -or ($Choice -ne "y")) {
                Write-Output "[!] Skipping [$Username]."
                return
            }
            Write-Output "[+] Continuing..."
        }

        Write-Output "[+] Setting password for [$Username]"
        Set-ADAccountPassword -identity $Username -NewPassword $securepass -Reset

        # User should exist so get the GUID
        $userguid = (Get-AdUser $Username).ObjectGUID 
        # Create UPN
        $UPN = $Username + '@' + $domain
        
        # Set basic properties for the created user
        Set-ADUser -Identity $Username -UserPrincipalName $UPN -Enabled 1
        Write-Output "[+] Basic user properties for [$Username] added"

        # Make Kerberoastable
        if ($SPN) {
            # TODO: Check SPN for uniqueness, or else the SPN does not set.
            $SPNs = $SPN.Split(',');
            foreach ($name in $SPNs) {
                Write-Output "[+] Setting SPN [$name] on user [$Username]"
                Set-ADUser -Identity $Username -ServicePrincipalNames @{Add = $name}
            }
            Write-Host "[+] [$Username] is now Kerberoastable"
        }

        # Make ASREPRoastable
        if ($ASREPRoastable) {
            Get-ADUser -Identity $Username | Set-ADAccountControl -DoesNotRequirePreAuth:$true
            Write-Host "[+] [$Username] is now ASREPRoastable"
        }

        # Make password never expire
        if ($PasswordNeverExpires) {
            Set-ADUser -Identity $Username -Passwordneverexpires 1
            Write-Host "[+] The password for [$Username] will never expire"
        }

        # Add entry for a fake file server
        if ($ProfilePath) {
            Set-ADUser -Identity $Username  -ProfilePath $ProfilePath
            Write-Host "[+] The profile path for [$Username] will be a deceptive file share"
        }
        
        # Add description if required
        if ($description) {
            Set-ADUser -Identity $Username -Description $description
            Write-Host "[+] Added description for [$Username]"
        }
        
        # If Destination OU is specified the move it
        if ($OU) {
            Move-DecoyObjectToOU -DecoyGUID $userguid -OU $OU -ObjectType "User"
        }

        # if Logonworkstations is specified, add it to user object
        if ($LogonWkst) {
            Set-ADUser -Identity $Username -Logonworkstations $LogonWkst
            Write-Host "[+] Added LogonWorkstations for [$Username]"
        }

        # Add Firstname, lastname, Telephone Number if they exist
        if ($FirstName) {
            Set-ADUser -Identity $Username -GivenName $FirstName
            Write-Host "[+] Added first name [$FirstName] to [$Username]"
        }

        if ($LastName) {
            Set-ADUser -Identity $Username -Surname $LastName
            Write-Host "[+] Added last name [$LastName] to [$Username]"
        }

        if ($TelephoneNumber) {
            Set-ADUser -Identity $Username -OfficePhone $TelephoneNumber
            Write-Host "[+] Added telephone number [$TelephoneNumber] to [$Username]"
        }

        # Set Email if it exists
        if ($Email) {
            Set-ADUser -Identity $Username -EmailAddress $Email
            Write-Host "[+] Added email [$Email] to [$Username]"
        }

        if ($groupname) {
            $grouparr = $groupname.split(',')
            foreach($group in $grouparr){
                Write-Host "[+] Checking group $group"
                Add-DecoyUserToGroup -Groupname $group -Username $Username
            }
        }

        # Log in a random number of times ranging from 10 to 50
        
        # Write-Output "[+] Adding user to [Print Operators] group temporarily"
        # Add-DecoyUserToGroup -Groupname "Print Operators" -Username $Username
        # $LogonCount = Get-Random -Minimum 10 -Maximum 50
        # $Creds = New-Object PSCredential $Username, $securepass
        # Write-Host "[+] Increasing logon count to [$LogonCount], this may take some time..."
        # for($i = 0; $i -le $LogonCount; $i++) {
        #     $j = Start-Job -Credential $Creds -ScriptBlock { Get-Date }
        #     # $j | Receive-Job
        #     Start-Sleep -Seconds 1
        #     $j | Stop-Job | Remove-Job
        # }
        # Write-Output "[+] Removing user from [Print Operators] group."
        # Remove-DecoyUserFromGroup -Groupname "Print Operators" -Username $Username

        # Enable enumeration detection
        if ($EnableEnumDetection) {
            Enable-ADEnumDetection -ObjectName $Username -ObjectType "User"
        }

        # Add user to global users table.
        $User = Get-ADUser -Identity $Username -Properties objectguid, objectsid
        $UserData = New-Object PSObject
        $UserData | Add-Member "name" $Username
        $UserData | Add-Member "guid" $User.objectguid
        $UserData | Add-Member "sid" $User.objectsid.Value
        $Script:Users += $UserData
    }
}

function Add-DecoyComputer {
    [CmdletBinding()]
    param (
        [String]
        $ComputerName,

        [String]
        $IPAddress,

        [String]
        $OSName,

        [String]
        $OSVersion,

        [String]
        $Servicepack,

        [String]
        $Domain,

        [String]
        $Description,

        [String]
        $OU,

        [Boolean]
        $CreateObject,

        [Boolean]
        $EnableEnumDetection
    )

    process {
        <#
            - Add decoy computer object with relevant properties
            - Move the computer object to the right OU
            - Output/send GUID and SID of computer object to backend
        #>
        Write-Output "[*] Checking computer [$ComputerName]"
        # Convert computer to uppercase just in case
        $ComputerUpper = $computerName.ToUpper()
    
        # Append for FQDN
        $ComputerFQDN = $ComputerUpper + "." + $Domain

        # Check if computer exists else quit
        # Only relevant for credentialed mode
        if (!(Test-DecoyComputer -computer $ComputerUpper)) { 
            Write-Output "[!] Computer Object [$ComputerName] not found."
            # Create object if in credential-less mode
            if ($CreateObject) {
                Write-Output "[+] Creating computer object for [$ComputerName]"
                New-ADComputer -Name $ComputerName
            }
            else {
                Write-Host "[!] Computer [$ComputerName] was not added by the CMC. Please rectify this and run the script again." -ForegroundColor Red
                Write-Host "[!] Skipping to next decoy..." -ForegroundColor Red
                return
            }
        }
        else { 
            $Choice = Read-Host -Prompt "[!] Computer [$ComputerName] already exists. Overwrite properties [Y/N]? "
            if(($Choice -ne "Y") -or ($Choice -ne "y")) {
                Write-Host "[!] Skipping computer [$ComputerName]." -ForegroundColor Red
                return
            }
            else {
                Write-Host "[+] Overwriting properties..."
            }
        }

        # Computer should exist so get the GUID
        $ComputerGUID = (Get-ADComputer $ComputerUpper).ObjectGUID 
        
        # Add these SPNs to the decoy computers
        $DecoySPNs = @{
            add = "HOST/$ComputerFQDN","HOST/$ComputerUpper",
                  "TERMSRV/$ComputerFQDN", "TERMSRV/$ComputerUpper",
                  "RestrictedKrbHost/$ComputerFQDN", "RestrictedKrbHost/$ComputerUpper", 
                  "WSMAN/$ComputerUpper", "WSMAN/$ComputerFQDN"
        }

        # Add basic properties to the computer objects
        if ($Servicepack) {
            Set-ADComputer  -Identity $ComputerUpper `
                            -OperatingSystemServicePack $servicepack `
                            -ServicePrincipalNames $DecoySPNs
        }
        else { 
            Set-ADComputer  -Identity $ComputerUpper `
                            -ServicePrincipalNames $DecoySPNs
        }
        Write-Output "[+] Basic computer properties for [$ComputerUpper] added"

        # Add OperatingSystem if provided
        if ($osname) {
            Write-Output "[+] OperatingSystem found so adding it"
            Set-ADComputer $ComputerUpper -OperatingSystem $osname
        }
        else {
            Write-Output "[+] No OperatingSystem Specified. Skipping.."
        }

        # Add OperatingSystemVersion if provided
        if ($osversion) {
            Write-Output "[+] OperatingSystemVersion found so adding it"
            Set-ADComputer $ComputerUpper -OperatingSystemVersion $osversion
        }
        else {
            Write-Output "[+] No OperatingSystemVersion Specified. Skipping.."
        }
        

        # Add DNS records, if IP supplied
        if($IPAddress) {
            try {
                # Check to see if DNS exists
                $answer = Resolve-DNSName -Name $ComputerName -Type A -ErrorAction Stop
                if($answer[0].IPAddress -ne $IPAddress) {
                    Write-Output "[+] Current DNS for [$ComputerName] is set to [$($answer[0].IPAddress)]"
                    Write-Output "[+] Changing IP to $IPAddress"
                    Set-DnsServerResourceRecordA -Name $ComputerName `
                                                -IPv4Address $IPAddress
                }
            }
            catch {
                Write-Output "[+] DNS Record does not exist. Creating..."
                Write-Output "[+] Adding record [$Computername] to [$IPAddress]"
                Add-DnsServerResourceRecordA -Name $ComputerName `
                                            -ZoneName $Domain `
                                            -CreatePtr `
                                            -IPv4Address $IPAddress
            }
        } 
        else {
            Write-Output "[+] No IP Address supplied for [$ComputerName]"
        }

        # Add properties over the basic ones

        # Add description if provided
        if ($Description) {
            Write-Output "[+] Description found so adding it"
            Set-ADComputer $ComputerUpper -Description $Description
        }
        else {
            Write-Output "[+] No description Specified. Skipping.."
        }

        # Check if a destination OU is given and move to it if it exists
        if ($OU) {
            Write-Output "[+] Attempting to move to $OU"
            Move-DecoyObjectToOU -DecoyGUID $ComputerGUID -OU $OU -ObjectType "Computer"
        }
        else {
            Write-Output "[+] No OU Specified so computer object remains unmoved"
        }

        # Setting msds-supportedEncryptionTypes to RC4, AES128 and AES256
        Set-ADComputer $ComputerUpper -KerberosEncryptionType RC4
        Set-ADComputer $ComputerUpper -KerberosEncryptionType AES128
        Set-ADComputer $ComputerUpper -KerberosEncryptionType AES256
        
        # Enable enumeration detection
        if ($EnableEnumDetection) {
            Enable-ADEnumDetection -ObjectName $ComputerName -ObjectType "Computer"
        }

        # Add Computer to Global computers array
        $Comp = Get-ADComputer -Identity $ComputerName -Properties objectguid, objectsid
        $CompData = New-Object PSObject
        $CompData | Add-Member "name" $Comp.name
        $CompData | Add-Member "guid" $Comp.objectguid
        $CompData | Add-Member "sid" $Comp.objectsid.Value
        $Script:Computers += $CompData

        # Reset computers
        $ResetCount = Get-Random -Minimum 2 -Maximum 15
        Write-Output "[+] Resetting computer account password [$ResetCount] times"
        for($i = 0; $i -lt $ResetCount; $i++) {
            dsmod computer $Comp.distinguishedName -reset
        }
    }
}

function Get-MenuTableEntry {
    [CmdletBinding()]
    param (
        [String]
        $Choice,

        [String]
        $Title,

        [String]
        $Description
    )
    process {
        $Entry = New-Object PSObject
        $Entry | Add-Member "Choice" $Choice
        $Entry | Add-Member "Title" $Title
        $Entry | Add-Member "Description" $Description
        return $Entry
    }
}

function Send-DeploymentJson {
    [CmdletBinding()]
    param (
        [String]
        [ValidateSet("API","Local")]
        $Mode,

        [String]
        $Domain,

        [String]
        $Receiver,

        [String]
        $Token
    )
    
    process {
        $Request = New-Object PSObject
        $Request | Add-Member "domain" $Domain
        $Request | Add-Member "added_users" $Script:Users
        $Request | Add-Member "added_computers" $Script:Computers
        $Request | Add-Member "removed_users" $Script:RemovedUsers
        $Request | Add-Member "removed_computers" $Script:RemovedComputers

        $JsonBody = $Request | ConvertTo-Json -Compress
        $ReceiverURL = "https://$Receiver/apiv1/ad-script-callback/deployment-json"
        $IWRHeaders = @{
            "Content-Type"="application/json";
            "X-CLIENT-AUTH"="$Token";
        } 

        switch($Mode) {
            "API" {
                try {
                    Invoke-WebRequest -Uri $ReceiverURL `
                                      -Method 'POST' `
                                      -Headers $IWRHeaders `
                                      -Body $JsonBody
                }
                catch {
                    Write-Output "[!] Error: $($_.Exception)"
                    Write-Host "[-] Failed to send user data to receiver. Saving locally..." -ForegroundColor Red
                    Send-DeploymentJson -Mode "Local" -Domain $Domain -Receiver $Receiver -Token $Token
                } 
            }
            "Local" {
                $Timestamp = Get-Date -Format 'ddmmyyyy_HHmm' 
                $FileName = "deployment_json_$($Timestamp).json"
                Write-Host "[+] Writing deployment JSON file to: $($FileName)" -ForegroundColor Green
                $JsonBody | Out-File -FilePath $FileName
            }
        }       
    }
}

#-----------------------------------------------------------------------------------------------#
#   Interactive part of the program starts below.
#-----------------------------------------------------------------------------------------------#

<#
    This will be the entry point with the menu
#>
function Start-Deployment {
    [CmdletBinding()]
    param ()
    
    process {
        Import-Module PSReadLine
        try {
            Import-Module ActiveDirectory
        }
        catch {
            Write-Host -ForegroundColor Yellow "'ActiveDirectory' Module was not found. Please **only** use Option 9 from the menu"
        }

        $UserAuditAttributes = @(
            "Last-Logon",
            "Service-Principal-Name",
            "Admin-Count",
            "Is-Critical-System-Object"
        )

        $ComputerAuditAttributes = @(
            "Service-Principal-Name",
            "Last-Logon",
            "When-Created"
        )

        $SendMode = "Local"
        $Receiver = "aurors.illusionblack.com"

        Resolve-AttributeGuids -UserAuditAttributes $UserAuditAttributes -ComputerAuditAttributes $ComputerAuditAttributes
        Test-DCAuditPolicies

        $Menu = @()
        $Menu += Get-MenuTableEntry -Choice "1" `
                                    -Title "Deploy decoy users" `
                                    -Description "Creates decoy users in your Active Directory as configured in the Central Management Console"
        $Menu += Get-MenuTableEntry -Choice "2" `
                                    -Title "Deploy decoy computers" `
                                    -Description "Creates decoy computer objects in your Active Directory and configures IP addresses for them in the DNS"
        $Menu += Get-MenuTableEntry -Choice "3" `
                                    -Title "Remove decoy users" `
                                    -Description "Removes decoy users that have just been deployed. Use this for clearing existing decoys."
        $Menu += Get-MenuTableEntry -Choice "4" `
                                    -Title "Remove decoy computers" `
                                    -Description "Removes decoy computers that have just been deployed. Use this for clearing existing decoys."
        $Menu += Get-MenuTableEntry -Choice "5" `
                                    -Title "Remove deleted decoy users" `
                                    -Description "Removes decoy users that have been deleted from the Central Management Console."
        $Menu += Get-MenuTableEntry -Choice "6" `
                                    -Title "Remove deleted decoy computers" `
                                    -Description "Removes decoy computers that have been deleted from the Central Management Console."
        $Menu += Get-MenuTableEntry -Choice "7" `
                                    -Title "Verify Deployment" `
                                    -Description "Verifies if the deployed users and computers have the correct properties."
        $Menu += Get-MenuTableEntry -Choice "8" `
                                    -Title "Generate deployment JSON" `
                                    -Description "Generates a deployment JSON with the properties of the decoy users and computers. Upload this JSON file to the CMC under Deceive > Active Directory Decoys > Actions > Upload Deployment JSON"
        $Menu += Get-MenuTableEntry -Choice "0" `
                                    -Title "Exit" `
                                    -Description "Exits this script."

        function Write-Menu {
            $Menu | Format-Table -Wrap
        }

        Write-Menu
        $Choice = Read-Host -Prompt "Action"
        while ($Choice -ne 0) {
            switch ($Choice) {
                1 {
                    # Users deployment
                    Add-DecoyUser -Username "avi_ad1" `
                                  -SPN "postgres/FINPREPROD.CHOICECORP.NET" `
                                  -LogonWkst "FINPREPROD" `
                                  -Domain "choicecorp.net" `
                                  -ProfilePath "\\PLESK-90\images" `
                                  -Description "" `
                                  -Groupname "Domain Admins,Enterprise Admins" `
                                  -Passwordneverexpires $false `
                                  -OU "" `
                                  -FirstName "a" `
                                  -LastName "b" `
                                  -TelephoneNumber "" `
                                  -Email "" `
                                  -ASREPRoastable $true `
                                  -EnableEnumDetection $true

                   $Choice = -1
                }
                2 {
                    # Computer deployment
                   $Choice = -1
                }
                3 {
                    Remove-DecoyUser -Username "avi_ad1" -Deployed $True
                   $Choice = -1
                }
                4 {
                   $Choice = -1
                }
                5 {
 
                    $Choice = -1
                }
                6 {

                    $Choice = -1
 
                }
                
                7 {
                    # Verify deployment
                    Test-DecoyUserDeployment -Username "avi_ad1" `
                                             -SPN "postgres/FINPREPROD.CHOICECORP.NET" `
                                             -LogonWkst "FINPREPROD" `
                                             -Domain "choicecorp.net" `
                                             -ProfilePath "\\PLESK-90\images" `
                                             -Description "" `
                                             -Groupname "Domain Admins,Enterprise Admins" `
                                             -Passwordneverexpires $false `
                                             -ASREPRoastable $true `
                                             -OU "" `
                                             -FirstName "a" `
                                             -LastName "b" `
                                             -TelephoneNumber "" `
                                             -Email ""
                    $Choice = -1
                }
                8 {
                    Send-DeploymentJson -Mode $SendMode -Domain "choicecorp.net" -Receiver $Receiver -Token "VQFG3MVLJOVM064DU2YW7VZ4CF5SWT1624J5211QDQM00J1K728JQTG3KDWWZVE1"
                    $Choice = -1
                }
                0 {
                    # Remove out the globals
                    Remove-Variable CompAuditGUIDS -Scope Script
                    Remove-Variable UserAuditGUIDS -Scope Script
                    Remove-Variable RemovedComputers -Scope Script
                    Remove-Variable RemovedUsers -Scope Script
                    Remove-Variable Computers -Scope Script
                    Remove-Variable Users -Scope Script
                    return
                }
                Default {
                    Write-Menu
                    $Choice = Read-Host -Prompt "Action"
                }
            }
        }
    }
}
