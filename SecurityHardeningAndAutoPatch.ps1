# Define the log file path
$logFile = "C:\Scripts\SecurityHardening.log"

# Function to log actions
function Log-Action {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -FilePath $logFile -Append
}

# 1. Disable LLMNR and NetBIOS
Log-Action "Disabling LLMNR and NetBIOS."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "Start" -Value 4
Log-Action "LLMNR and NetBIOS disabled."

# 2. Disable SMBv1
Log-Action "Disabling SMBv1."
Disable-WindowsOptionalFeature -Online -FeatureName FS-SMB1
Log-Action "SMBv1 disabled."

# 3. Enforce Strong Password Policies
Log-Action "Enforcing strong password policies."
$minLength = 14
$complexityEnabled = 1
$maxAge = 90

# Set minimum password length
net accounts /minpwlen:$minLength

# Enable password complexity requirements
net accounts /passwordchg:yes

# Set maximum password age
net accounts /maxpwage:$maxAge
Log-Action "Strong password policies enforced."

# 4. Protect LSASS (Credential Guard)
Log-Action "Ensuring Credential Guard is enabled."
# Placeholder: Credential Guard needs to be enabled via Group Policy or Windows Features.
Write-Output "Ensure Credential Guard is enabled via Group Policy or Windows Features."
Log-Action "Credential Guard configuration noted."

# 5. Restrict Admin Account Usage (deny RDP access)
Log-Action "Restricting RDP access for local administrators."
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "DenyLocalAdmin" -PropertyType "DWORD" -Value 1 -Force
Log-Action "RDP access restriction set."

# 6. Limit Local Administrators
Log-Action "Limiting local administrator accounts."
$admins = Get-LocalGroupMember -Group "Administrators"
foreach ($admin in $admins) {
    if ($admin.name -notlike "Administrator" -and $admin.name -notlike "Domain Admins") {
        Remove-LocalGroupMember -Group "Administrators" -Member $admin.name
    }
}
Log-Action "Local administrators limited."

# 7. Rename Default Administrator Account
Log-Action "Renaming default Administrator account."
Rename-LocalUser -Name "Administrator" -NewName "AdminAccountRenamed"
Log-Action "Default Administrator account renamed."

# 8. Disable Unused Admin Accounts
Log-Action "Disabling unused admin accounts."
$unusedAdmins = @("AdminOld", "AdminBackup") # Replace with actual admin accounts to be disabled
foreach ($account in $unusedAdmins) {
    Disable-LocalUser -Name $account
}
Log-Action "Unused admin accounts disabled."

# 9. Enable AppLocker (Basic Policy)
Log-Action "Enabling AppLocker."
# Requires Windows Enterprise or Education
$applockerPolicy = @"
<ApplockerPolicy xmlns="http://schemas.microsoft.com/Windows/2008/Applocker">
    <Rules>
        <Executable>
            <Allow>
                <Publisher>
                    <Name>*</Name>
                </Publisher>
            </Allow>
        </Executable>
    </Rules>
</ApplockerPolicy>
"@
Set-AppLockerPolicy -XMLPolicy $applockerPolicy -Merge
Log-Action "AppLocker policy enabled."

# 10. Enable Logging and Monitoring
Log-Action "Configuring event logging."
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
Log-Action "Event logging configured."

# 11. Configure Sysmon (System Monitor)
Log-Action "Configuring Sysmon."
# Placeholder: Ensure Sysmon is installed and configured with a custom configuration file.
Write-Output "Ensure Sysmon is installed and configured with a custom configuration file."
Log-Action "Sysmon configuration noted."

# 12. Remove Stored Credentials
Log-Action "Removing stored credentials."
cmdkey /list | ForEach-Object {
    $cred = $_ -split ':'
    if ($cred[0].Trim() -eq "Target") {
        cmdkey /delete:$cred[1].Trim()
    }
}
Log-Action "Stored credentials removed."

# 13. Restrict Access to Sensitive Files
Log-Action "Restricting access to sensitive files."
$restrictedFiles = @("C:\Windows\System32\config\SAM", "C:\Windows\System32\config\SYSTEM")
foreach ($file in $restrictedFiles) {
    icacls $file /inheritance:r /remove:g "Everyone"
}
Log-Action "Access to sensitive files restricted."

# 14. Automatic Windows Updates
Log-Action "Checking for and installing Windows updates."

# Ensure the Windows Update service is running
Start-Service -Name wuauserv

# Install the Windows Update module
Install-Module -Name PSWindowsUpdate -Force -Confirm:$false

# Import the module
Import-Module PSWindowsUpdate

# Check for updates and install them
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
Log-Action "Windows updates checked and installed."

# Log Script Completion
Log-Action "Security hardening script executed and completed."
Write-Output "System hardened and updates applied. Please review the log for details."
