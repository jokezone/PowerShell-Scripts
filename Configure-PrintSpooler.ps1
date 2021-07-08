<#
.SYNOPSIS
    This script is intended to mitigate Print Spooler attacks (specifically PrintNightmare CVE-2021-34527) 
by disabling the Spooler service where it is not needed (non-Print Server servers & DCs). Note: The 
Spooler service on Domain Controllers is responsible for pruning of printer objects published to 
Active Directory. The goal is to only make the minimum amount of changes based on the type of system.
Exceptions can be managed using an Active Directory security group.

    Author: Thomas Connell

.DESCRIPTION
    This script will enable Print Service debug logging and stop and disable the Print Spooler
service on all Windows Server operating systems that do not have the Print Server feature
installed. If the Spooler service is found to be running on non-Print Servers, and the Spooler 
service is allowed to accept client connections, it will restrict SYSTEM access to the Spooler 
drivers directory. If you need to perform configuration changes that require the spooler service 
to write to this directory, the ACL can be removed temporarily and it will be re-added the next 
time the mitigation script runs. This is designed to be deployed to all Windows clients via a GPO 
Preference Scheduled Task which runs under the SYSTEM context.

Recommendation: Set the 'Allow Print Spooler to accept client connections' GPO setting to disabled 
on all domain workstations to disable inbound remote printing. This mitigates the remote code execution
aspect of the PrintNightmare CVE. This setting will block users from sharing printers directly attached
to their computer, but still allows them to print locally. Add computers to the AD exception group if
they need to share printers.

.LINK
    Source project:
    https://github.com/jokezone
    Microsoft:
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
    Threat Post:
    https://threatpost.com/poc-exploit-windows-print-spooler-bug/167430/
    Sysmon exploit detection:
    https://github.com/LaresLLC/CVE-2021-1675/blob/main/CVE-2021-1675.xml

.PARAMETER LogDir
    Directory to send PowerShell transaction logs for debug/testing. Defaults to Windows/Temp directory when
    running as a SYSTEM scheduled task.
.PARAMETER ServerLogDir
    Optionally send non-Print Server transaction logs to a different folder.
.PARAMETER PrintServerLogDir
    Optionally send Print Server transaction logs to a different folder.
.PARAMETER CriticalChangeOrFailureLogDir
    Optionally send any script critical change or failure events to another location for review.
.PARAMETER EnablePrintServiceLog
    Enables the Microsoft-Windows-PrintService/Operational debug log for detecting malicious print driver installs.
.PARAMETER DisableRemotePrint
    Disables Remote Print on non-Print Servers to mitigate the remote code execution aspect of the PrintNightmare CVE.
.PARAMETER SecurePointAndPrint
    Confirms PointAndPrint is secured against known attacks.
.PARAMETER PointAndPrintADExceptionGroup
    Check if the computer running the script is a direct member of an AD exception group.
    Exception group members will have PointAndPrint settings modified by the script.
.PARAMETER SpoolerADExceptionGroup
    Check if the computer running the script is a direct member of an AD exception group.
    Exception group members will have the Spooler service enabled/started and will get the SYSTEM deny ACE set.
.PARAMETER RemoveACL
    Remove the SYSTEM deny ACE on the spool/drivers folder if it exists.
.PARAMETER AlwaysSetACL
    Set the SYSTEM deny ACE on the spool/drivers folder if it does not exist.
.PARAMETER RestartSpooler
    If the Print Spooler service is running for more than 24 hours, this switch will restart it. Some changes to
    the Spooler service configuration require the service to be restarted.
.PARAMETER WhatIf
    Logs all actions without actually making any changes. Useful for testing/debugging.

.EXAMPLE
    PS C:\> Configure-PrintSpooler.ps1 -RestartSpooler
    - Stop and disable the Print Spooler service on all server OSes that do not have the Print Server 
    feature installed. If the Spooler service is running, it will restrict SYSTEM access to the Spooler 
    drivers directory. Finally, the Spooler service will be restarted.
.EXAMPLE
    PS C:\> Configure-PrintSpooler.ps1 -EnablePrintServiceLog -SpoolerADExceptionGroup "Print-Spooler-Exceptions"
    - Same as the above example plus enables the Microsoft-Windows-PrintService/Operational log
    and if the computer is a direct member of the AD exception group, the Print Spooler will remain
    running, but a SYSTEM deny ACE will be placed on the spool/drivers folder to prevent exploitation.
.EXAMPLE
    PS C:\> Configure-PrintSpooler.ps1 -RemoveACL
    - Remove the SYSTEM deny ACE on the spool/drivers folder if it exists.
.EXAMPLE
    PS C:\> PowerShell.exe -File "\\Path\To\Script\Configure-PrintSpooler.ps1" -EnablePrintServiceLog
    - Method to launch the script from a file share without any user interaction.
    - It can be deployed to an entire domain via a GPO preference scheduled task that runs as SYSTEM.
    - Host the script somewhere all computers on your domain can access it (e.g. NETLOGON share).
#>
param
(
    [string]
    $LogDir = $env:TEMP,
    [string]
    $ServerLogDir = "",
    [string]
    $PrintServerLogDir = "",
    [string]
    $CriticalChangeOrFailureLogDir = "",
    [string]
    $PointAndPrintADExceptionGroup = "",
    [string]
    $SpoolerADExceptionGroup = "",
    [switch]
    $EnablePrintServiceLog,
    [switch]
    $DisableRemotePrint,
    [switch]
    $SecurePointAndPrint,
    [switch]
    $RemoveACL,
    [switch]
    $AlwaysSetACL,
    [switch]
    $RestartSpooler,
    [switch]
    $WhatIf
)

function Write-Message ([string]$message,[string]$messagetype) {
    switch ($messagetype) {
        info {Write-Output $message}
        warning {Write-Warning $message}
        critical {Write-Warning $message}
    }
    [string]$logDate = (Get-Date).ToString("u")
    if ($CriticalChangeOrFailureLogDir -and $messagetype -eq "critical") {
        $eventlog = $CriticalChangeOrFailureLogDir + "\$ENV:COMPUTERNAME-Configure-PrintSpooler-CriticalChangeOrFailure-Log.txt"
        "`r`n$logDate - $message" | Out-File -FilePath $eventlog -Append
    }
}

# Detect OS type
$Role = (Get-WmiObject Win32_ComputerSystem).DomainRole
if ($Role -eq 1) {$OSType = "workstation"}
if ($Role -eq 3) {$OSType = "memberserver"}
if ($Role -ge 4) {$OSType = "domaincontroller"}

# Detect if print services feature is installed
$PrintServer = Get-WmiObject -Query "select * FROM Win32_ServerFeature WHERE ID=135" -ErrorAction SilentlyContinue

# Transcript logging
if (($OSType -ne "workstation") -and $ServerLogDir) {$LogDir = $ServerLogDir}
if ($PrintServer -and $PrintServerLogDir) {$LogDir = $PrintServerLogDir}
if (-not(Test-Path $LogDir)) {$LogDir = $env:TEMP}
$LogFile = $LogDir + "\$ENV:COMPUTERNAME-Configure-PrintSpooler-Log.txt"
if (Test-Path -Path $LogFile)
{   #Delete log file if it grows too large
    Get-ChildItem $LogFile | Where-Object Length -gt 2048000 | Remove-Item -Confirm:$false
}
Start-Transcript $LogFile -Append

if ($WhatIf) {
    [string]$message = "WhatIf switch used; No changes are actually being made."
    Write-Message $message info
}

# Check the 'Allow Print Spooler to accept client connections' GPO setting (disabled = 2)
$RemotePrintPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" | Select-Object -ExpandProperty "RegisterSpoolerRemoteRpcEndPoint" -ErrorAction SilentlyContinue

if ($SpoolerADExceptionGroup -ne "" -or $PointAndPrintADExceptionGroup -ne "") {
    # Check if the computer running the script is a direct member of an AD exception group
    Try {
        # Query AD for group membership of computer
        $domainDN = ([ADSI]"").distinguishedName
        $root = [ADSI]"LDAP://$domainDN"
        $search = [adsisearcher]$root
        $Search.Filter = "(&(SamAccountName=$ENV:COMPUTERNAME$))"
        $computer = $Search.FindOne()
        $computerproperties = $computer.Properties
        [array]$groups = $computerproperties.memberof

        if ($SpoolerADExceptionGroup -ne "") {
            $SpoolerException = $false
            [string]$message = "Print Spooler AD exception group to match: $SpoolerADExceptionGroup"
            Write-Message $message info
            if ($groups -match "CN=$SpoolerADExceptionGroup.*") {
                [string]$message = "$ENV:COMPUTERNAME's group membership: $groups"
                Write-Message $message info
                Try {
                    $SpoolerException = $true
                    if (-not($WhatIf)) {
                        Set-Service -Name Spooler -StartupType Automatic -Verbose -ErrorAction Stop
                        Get-Service -Name Spooler | Start-Service -Verbose -ErrorAction Stop
                    }
                    [string]$message = "$ENV:COMPUTERNAME is in the AD exception group; Print Spooler service will remain enabled and started"
                    Write-Message $message critical
                } Catch {
                    [string]$message = "Failed to enable and start the Print Spooler service because $($_.Exception.Message)"
                    Write-Message $message critical
                }
            }
        }

        if ($PointAndPrintADExceptionGroup -ne "") {
            $PointAndPrintException = $false
            [string]$message = "PointAndPrint AD exception group to match: $PointAndPrintADExceptionGroup"
            Write-Message $message info
            if ($groups -match "CN=$PointAndPrintADExceptionGroup.*") {
                [string]$message = "$ENV:COMPUTERNAME's group membership: $groups"
                Write-Message $message info
                $PointAndPrintException = $true
            }
        }
    } Catch {
        [string]$message = "Unable to query AD for group membership. Mitigations will be skipped."
        Write-Message $message critical
        $ADQueryFailed = $true
    }
}

# Enable Print Service debug logging for event ID 808 and 316 collection
if ($EnablePrintServiceLog) {
    $PrintServiceLog = Get-WinEvent -ListLog "Microsoft-Windows-PrintService/Operational" -Force -ErrorAction SilentlyContinue
    if ($PrintServiceLog.IsEnabled -eq $false) {
        Try {
            if (-not($WhatIf)) {
                $PrintServiceLog.set_IsEnabled($true) | Out-Null
                $PrintServiceLog.SaveChanges()
            }
            [string]$message = "Successfully enabled log $($PrintServiceLog.logname)"
            Write-Message $message info
        } Catch {
            [string]$message = "Failed to enable $($PrintServiceLog.logname) because $($_.Exception.Message)"
            Write-Message $message critical
        }
    }
    else {
        [string]$message = "$($PrintServiceLog.logname) logging is already enabled"
        Write-Message $message info
    }
}

# Stop and disable Spooler service on all server OSes that do not have the Print Services feature installed
if (($OSType -ne "workstation") -and (-not($PrintServer)) -and (-not($SpoolerException)) -and (-not($ADQueryFailed -eq $true))) {
    if (Get-Service -Name Spooler | Where-Object Status -eq "Running") {
        Try {
            if (-not($WhatIf)) {
                Get-Service -Name Spooler | Stop-Service -Force -Verbose -ErrorAction Stop
                Set-Service -Name Spooler -StartupType Disabled -Verbose -ErrorAction Stop
            }
            [string]$message = "Print Spooler service has been stopped and disabled"
            Write-Message $message info
        } Catch {
            [string]$message = "Failed to stop and disable the Print Spooler service because $($_.Exception.Message)"
            Write-Message $message critical
        }
    } else {
        [string]$message = "The Print Spooler service is already stopped."
        Write-Message $message info
    }
}

if ($PrintServer -and ($OSType -eq "domaincontroller")) {
    [string]$message = "Failure: This host has been detected as a Print Server and a Domain Controller. If you are responsible for this, please proceed directly to HR and turn in your ID card."
    Write-Message $message critical
}

if ($PrintServer) {
    # Configure the RestrictDriverInstallationToAdministrators registry value to prevent non-administrators from installing printer drivers on a print server.
    # https://support.microsoft.com/topic/31b91c02-05bc-4ada-a7ea-183b129578a7
    [string]$message = "This host has been detected as a Print Server."
    Write-Message $message info

    # Verify the Print Spooler service is running on the print server
    if (-not(Get-Service -Name Spooler | Where-Object Status -eq "Running")) {
        [string]$message = "The print server Print Spooler service was stopped; Starting the service."
        Write-Message $message critical
        if (-not($WhatIf)) {
            Try {
                Set-Service -Name Spooler -StartupType Automatic -Verbose -ErrorAction Stop
                Get-Service -Name Spooler | Start-Service -Verbose -ErrorAction Stop
            } Catch {
                [string]$message = "Failed to start the Print Spooler service because $($_.Exception.Message)"
                Write-Message $message critical
            }
        }
    } else {
        [string]$message = "The print server Print Spooler service is running"
        Write-Message $message info
    }

    if (-not(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint")) {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" | Out-Null
    }

    $PrintDriverInstallPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" | Select-Object -ExpandProperty "RestrictDriverInstallationToAdministrators" -ErrorAction SilentlyContinue
    if ($PrintDriverInstallPolicy -ne "1") {
        [string]$message = "Setting RestrictDriverInstallationToAdministrators registry value to prevent non-administrators from installing printer drivers on a print server."
        Write-Message $message info
        if (-not($WhatIf)) {
            Try {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
            } Catch {
                [string]$message = "Failed to set the RestrictDriverInstallationToAdministrators registry value because $($_.Exception.Message)"
                Write-Message $message critical
            }
        }
    } else {
        [string]$message = "The RestrictDriverInstallationToAdministrators registry value is already set to prevent non-administrators from installing printer drivers on a print server."
        Write-Message $message info
    }
}

# Point And Print restrictions for CVE-2021-34527 RCE
if ($SecurePointAndPrint -and (-not($PointAndPrintException)) -and (-not($ADQueryFailed -eq $true))) {
    if (Get-Service -Name Spooler | Where-Object Status -eq "Running") {
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint") {
            # Get all the Point And Print policy settings from the registry
            $PointAndPrintPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -ErrorAction SilentlyContinue
            if ($PointAndPrintPolicy.Restricted -eq "0") {
                [string]$message = "Failure: Point And Print restrictions are currently disabled on this host. This needs to be investigated."
                Write-Message $message critical
            }
        } else {
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" | Out-Null
        }

        if (($PointAndPrintPolicy.NoWarningNoElevationOnInstall -ne "0") -or ($PointAndPrintPolicy.UpdatePromptSettings -ne "0") -or ($PointAndPrintPolicy.NoWarningNoElevationOnUpdate -ne "0")) {
            [string]$message = "Enabled Point And Print security prompts."
            Write-Message $message info
            if (-not($WhatIf)) {
                Try {
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "Restricted" -Value 1 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Value 0 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Value 0 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnUpdate" -Value 0 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
                } Catch {
                    [string]$message = "Failed to set the Point And Print security prompt registry values because $($_.Exception.Message)"
                    Write-Message $message critical
                }
            }
        } else {
            [string]$message = "Point And Print security prompts are already enabled on this host."
            Write-Message $message info
        }
    }
}

# Remote Print restrictions for mitigating CVE-2021-34527 RCE
# This is the same as setting the 'Allow Print Spooler to accept client connections' GPO setting to disabled
if ($DisableRemotePrint -and (-not($PrintServer)) -and (-not($ADQueryFailed -eq $true))) {
    if (Get-Service -Name Spooler | Where-Object Status -eq "Running") {
        if ($RemotePrintPolicy -ne "2") {
            [string]$message = "Disabled Remote Print."
            Write-Message $message info
            if (-not($WhatIf)) {
                Try {
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -Value 2 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
                } Catch {
                    [string]$message = "Failed to set the Remote Print registry value because $($_.Exception.Message)"
                    Write-Message $message critical
                }
            }
        } else {
            [string]$message = "Remote Print is already disabled on this host."
            Write-Message $message info
        }
    }
}

# Confirm Windows User Account Controls (UAC) is enabled HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA = 1
if (Get-Service -Name Spooler | Where-Object Status -eq "Running") {
    if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object -ExpandProperty "EnableLUA") -ne "1") {
        [string]$message = "Failure: Windows User Account Controls (UAC) is not enabled on this host."
        Write-Message $message critical
    } else {
        [string]$message = "Windows User Account Controls (UAC) is enabled."
        Write-Message $message info
    }
}

# If the Spooler service is running, and remote print is allowed, restrict SYSTEM access to the Spooler drivers directory
# Source: https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/

# Re-check the 'Allow Print Spooler to accept client connections' GPO setting (disabled = 2)
$RemotePrintPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" | Select-Object -ExpandProperty "RegisterSpoolerRemoteRpcEndPoint" -ErrorAction SilentlyContinue

if ((-not($ADQueryFailed -eq $true)) -and (-not($PrintServer)) -and (($RemotePrintPolicy -ne "2") -or ($SpoolerException -eq $true) -or ($AlwaysSetACL -eq $true))) {
    # The Print Spooler is allowed to accept client connections, this system has a Spooler exception or the AlwaysSetACL switch was used.
    # If the AD query fails or this is a print server, do not set the ACL because it could cause issues.
    if (Get-Service -Name Spooler | Where-Object Status -eq "Running") {
        Try {
            $Path = "C:\Windows\System32\spool\drivers"
            $Acl = (Get-Item $Path).GetAccessControl('Access')
            # Only run if the SYSTEM deny ACE is not present D:PAI(D;OICI;CCDCLCSWRPWPLOCRSDRC;;;SY)
            if ($Acl.AccessToString -notmatch "NT AUTHORITY\\SYSTEM Deny  Modify") {
                if (-not($WhatIf)) {
                    $Ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit, ObjectInherit", "None", "Deny")
                    $Acl.AddAccessRule($Ar) | Out-Null
                    Set-Acl $Path $Acl -ErrorAction Stop
                }
                [string]$message = "The system meets criteria for updating the spool\drivers ACL; Restricted SYSTEM access to the Print Spooler drivers directory."
                Write-Message $message critical
            } else {
                [string]$message = "ACL already set; SYSTEM access to the Print Spooler drivers directory is restricted."
                Write-Message $message info
            }
        } Catch {
            [string]$message = "Failed to restrict SYSTEM access to the Print Spooler drivers directory because $($_.Exception.Message)"
            Write-Message $message critical
        }
    }
}

if ((($RemotePrintPolicy -eq "2") -and (-not($SpoolerException))) -or ($RemoveACL)) {
    # Remote print is disabled, this system does not have a Spooler exeption, or the RemoveACL switch was used.
    Try {
        $Path = "C:\Windows\System32\spool\drivers"
        $Acl = (Get-Item $Path).GetAccessControl('Access')
        # Only run if the SYSTEM deny ACE is not present D:PAI(D;OICI;CCDCLCSWRPWPLOCRSDRC;;;SY)
        if ($Acl.AccessToString -match "NT AUTHORITY\\SYSTEM Deny  Modify") {
            if (-not($WhatIf)) {
                $Ar = New-Object  System.Security.AccessControl.FileSystemAccessRule("System", "Modify", "ContainerInherit, ObjectInherit", "None", "Deny")
                $Acl.RemoveAccessRule($Ar) | Out-Null
                Set-Acl $Path $Acl -ErrorAction Stop
            }
            [string]$message = "Removed restriction of SYSTEM access to the Print Spooler drivers directory"
            Write-Message $message info
        } else {
            [string]$message = "ACL removal not required; SYSTEM has access to the Print Spooler drivers directory"
            Write-Message $message info
        }
    } Catch {
        [string]$message = "Failed to remove SYSTEM access restriction on the Print Spooler drivers directory because $($_.Exception.Message)"
        Write-Message $message critical
    }
}

if ($RestartSpooler) {
    if (Get-Service -Name Spooler | Where-Object Status -eq "Running") {
        if ((Get-Process spoolsv).StartTime -lt (Get-Date).AddHours(-24)) {
            # Only run if the Spooler service has been running for more than 24 hours.
            [string]$message = "Restarting the Print Spooler service; Service has been running since $((Get-Process spoolsv).StartTime)"
            Write-Message $message info
            if (-not($WhatIf)) {
                Try {
                    Get-Service -Name Spooler | Stop-Service -Force -Verbose -ErrorAction Stop
                    Get-Service -Name Spooler | Start-Service -Verbose -ErrorAction Stop
                } Catch {
                    [string]$message = "Failed to restart the Print Spooler service because $($_.Exception.Message)"
                    Write-Message $message critical
                }
            }
        } else {
            [string]$message = "Print Spooler service is within the 1 day restart threshold; Service has been running since $((Get-Process spoolsv).StartTime)"
            Write-Message $message info
        }
    } else {
        [string]$message = "Unable to restart because the Print Spooler service is not running"
        Write-Message $message info
    }
}

Stop-Transcript
