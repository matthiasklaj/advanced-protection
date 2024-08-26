# Security Hardening and Automatic Patching Script

This PowerShell script, `SecurityHardeningAndAutoPatch.ps1`, is designed to enhance the security of Windows systems by implementing a series of hardening measures and automatically applying Windows updates. The script includes logging for auditing purposes and can be scheduled to run regularly to ensure continuous protection.

## Features

- **Disables Insecure Protocols**: LLMNR, NetBIOS, and SMBv1 are disabled to reduce attack surfaces.
- **Enforces Strong Password Policies**: Sets minimum password length, enables password complexity, and limits password age.
- **Protects LSASS**: Ensures Credential Guard is noted for protection against credential theft (requires additional setup).
- **Restricts RDP Access**: Limits RDP access for local administrators to prevent unauthorized remote access.
- **Limits Local Administrators**: Removes unnecessary local administrator accounts.
- **Renames Default Administrator Account**: Renames the default "Administrator" account to make it harder for attackers to identify.
- **Disables Unused Admin Accounts**: Disables specified admin accounts that are not in use.
- **Enables AppLocker**: Implements basic AppLocker policy to restrict unauthorized software execution (requires Windows Enterprise or Education).
- **Configures Event Logging and Monitoring**: Enables logging for critical security events, such as logon/logoff and object access.
- **Automatic Windows Updates**: Automatically checks for, downloads, and installs Windows updates to ensure the system is up to date.
- **Removes Stored Credentials**: Deletes stored credentials that could be exploited by attackers.
- **Restricts Access to Sensitive Files**: Restricts access to critical system files like `SAM` and `SYSTEM`.

## Requirements

- **PowerShell 5.1 or higher**
- **Administrative Privileges**: The script must be run with administrator rights.
- **PSWindowsUpdate Module**: This module is used to manage Windows updates.

## Installation

1. **Download the Script**: Save the script as `SecurityHardeningAndAutoPatch.ps1`.
2. **Move to Desired Location**: Place the script in a secure directory, e.g., `C:\Scripts`.
3. **Schedule for Regular Execution (Optional)**: Use Task Scheduler to run the script on a regular basis for continuous security enforcement.

## Usage

1. **Run the Script**:
   - Open PowerShell as an Administrator.
   - Navigate to the directory where the script is saved.
   - Execute the script by typing `.\SecurityHardeningAndAutoPatch.ps1`.

2. **Review Logs**:
   - The script logs all actions to `C:\Scripts\SecurityHardening.log`. Review this log for details on what the script has done.
