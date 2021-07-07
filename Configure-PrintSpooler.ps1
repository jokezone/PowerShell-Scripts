<#
.SYNOPSIS
    Script used to mitigate the July 2021 PrintNightmare CVE-2021-34527 exploit
which allows any domain user to remotely elevate to SYSTEM on any Windows
host running the Print Spooler service. The exploit works by dropping a DLL
in a subdirectory under C:\Windows\System32\spool\drivers.

    Author: Thomas Connell

.DESCRIPTION
    This script will enable Print Service debug logging and stop and disable the Print Spooler
service on all Windows Server operating systems that do not have the Print Server feature
installed. If the Spooler service is found to be running on non-Print Servers, it will restrict
SYSTEM access to the Spooler drivers directory. If you need to perform configuration changes
that require the spooler service to write to this directory, the ACL can be removed temporarily and it
will be re-added the next time the mitigation script runs. This is designed to be deployed to
all Windows clients via a GPO Preference Scheduled Task which runs under the SYSTEM context.

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
.PARAMETER EnablePrintServiceLog
    Enables the Microsoft-Windows-PrintService/Operational debug log for detecting malicious print driver installs.
.PARAMETER ADExceptionGroup
    Check if the computer running the script is a direct member of an AD exception group.
    Exception group members will have the Spooler service enabled/started and will get the SYSTEM deny ACE set.
.PARAMETER RemoveACL
    Remove the SYSTEM deny ACE on the spool/drivers folder if it exists.
.PARAMETER AlwaysSetACL
    Set the SYSTEM deny ACE on the spool/drivers folder if it does not exists.
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
    PS C:\> Configure-PrintSpooler.ps1 -EnablePrintServiceLog -ADExceptionGroup "Print-Spooler-Exceptions"
    - Same as the above example plus enables the Microsoft-Windows-PrintService/Operational log
    and if the computer is a direct member of the AD exception group, the Print Spooler will remain
    running, but a SYSTEM deny ACE will be placed on the spool/drivers folder to prevent exploitation.
.EXAMPLE
    PS C:\> Configure-PrintSpooler.ps1 -RemoveACL
    - Remove the SYSTEM deny ACE on the spool/drivers folder if it exists.
.EXAMPLE
    PS C:\> PowerShell.exe -File "\\Path\To\Script\Configure-PrintSpooler.ps1" -EnablePrintServiceLog}
    - Method to launch the script from a file share without any user interaction
#>
param
(
    [string]
    $LogDir = $env:TEMP,
    [string]
    $ServerLogDir = "",
    [string]
    $PrintServerLogDir = "",
    [switch]
    $EnablePrintServiceLog = $false,
    [string]
    $ADExceptionGroup = "",
    [switch]
    $RemoveACL,
    [switch]
    $AlwaysSetACL,
    [switch]
    $RestartSpooler,
    [switch]
    $WhatIf
)

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
    Write-Output "WhatIf switch used; No changes are actually being made."
}

# Check the 'Allow Print Spooler to accept client connections' GPO setting (disabled = 2)
$RemotePrintPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" | Select-Object -ExpandProperty "RegisterSpoolerRemoteRpcEndPoint" -ErrorAction SilentlyContinue

if ($ADExceptionGroup -ne "") {
    # Check if the computer running the script is a direct member of the AD exception group
    # Exception group members will have the Spooler service enabled/started and will get the SYSTEM deny ACE set
    Try {
        # Query AD for group membership of computer
        $domainDN = ([ADSI]"").distinguishedName
        $root = [ADSI]"LDAP://$domainDN"
        $search = [adsisearcher]$root
        $Search.Filter = "(&(SamAccountName=$ENV:COMPUTERNAME$))"
        $computer = $Search.FindOne()
        $computerproperties = $computer.Properties
        [array]$groups = $computerproperties.memberof

        # Set script parameters
        $SpoolerException = $false
        Write-Output "AD exception group to match: $ADExceptionGroup"
        if ($groups -match "CN=$ADExceptionGroup.*") {
            Write-Output "$ENV:COMPUTERNAME's group membership: $groups"
            Try {
                $SpoolerException = $true
                if (-not($WhatIf)) {
                    Set-Service -Name Spooler -StartupType Automatic -Verbose -ErrorAction Stop
                    Get-Service -Name Spooler | Start-Service -Verbose -ErrorAction Stop
                }
                Write-Output "$ENV:COMPUTERNAME is in the AD exception group; Print Spooler service will remain enabled and started"
            } Catch {
                Write-Warning "Failed to enable and start the Print Spooler service because $($_.Exception.Message)"
            }
        }
    } Catch {
        Write-Host "Unable to query AD for group membership. Print Spooler mitigations will be skipped."
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
            Write-Output "Successfully enabled log $($PrintServiceLog.logname)"
        } Catch {
            Write-Warning "Failed to enable $($PrintServiceLog.logname) because $($_.Exception.Message)"
        }
    }
    else {
        Write-Output "$($PrintServiceLog.logname) logging is already enabled"
    }
}

# Stop and disable Spooler service on all server OSes that do not have the Print Services feature installed
if (($OSType -ne "workstation") -and (-not($PrintServer)) -and ($SpoolerException -eq $false) -and (-not($ADQueryFailed))) {
    if (Get-Service -Name Spooler | Where-Object Status -eq "Running") {
        Try {
            if (-not($WhatIf)) {
                Get-Service -Name Spooler | Stop-Service -Force -Verbose -ErrorAction Stop
                Set-Service -Name Spooler -StartupType Disabled -Verbose -ErrorAction Stop
            }
            Write-Output "Print Spooler service has been stopped and disabled"
        } Catch {
            Write-Warning "Failed to stop and disable the Print Spooler service because $($_.Exception.Message)"
        }
    } else {
        Write-Output "The Print Spooler service is already stopped."
    }
}

if ($PrintServer -and ($OSType -eq "domaincontroller")) {
    Write-Warning "FAIL: This host has been detected as a Print Server and a Domain Controller. If you are responsible for this, please proceed directly to HR and turn in your ID card."
}

if ($PrintServer -and (Get-Service -Name Spooler | Where-Object Status -eq "Running")) {
    # Configure the RestrictDriverInstallationToAdministrators registry value to prevent non-administrators from installing printer drivers on a print server.
    # https://support.microsoft.com/topic/31b91c02-05bc-4ada-a7ea-183b129578a7
    Write-Output "This host has been detected as a Print Server."

    if (-not(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint")) {
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" | Out-Null
    }

    $PrintDriverInstallPolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" | Select-Object -ExpandProperty "RestrictDriverInstallationToAdministrators" -ErrorAction SilentlyContinue
    if ($PrintDriverInstallPolicy -ne "1") {
        Write-Output "Setting RestrictDriverInstallationToAdministrators registry value to prevent non-administrators from installing printer drivers on a print server."
        if (-not($WhatIf)) {
            Try {
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "RestrictDriverInstallationToAdministrators" -Value 1 -PropertyType DWORD -Force -ErrorAction Stop | Out-Null
            } Catch {
                Write-Warning "Failed to set the RestrictDriverInstallationToAdministrators registry value because $($_.Exception.Message)"
            }
        }
    } else {
        Write-Output "The RestrictDriverInstallationToAdministrators registry value is already set to prevent non-administrators from installing printer drivers on a print server."
    }
}

# If the Spooler service is running, and remote print is allowed, restrict SYSTEM access to the Spooler drivers directory
# Source: https://blog.truesec.com/2021/06/30/fix-for-printnightmare-cve-2021-1675-exploit-to-keep-your-print-servers-running-while-a-patch-is-not-available/

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
                Write-Output "The system meets criteria for updating the spool\drivers ACL; Restricted SYSTEM access to the Print Spooler drivers directory."
            } else {
                Write-Output "ACL already set; SYSTEM access to the Print Spooler drivers directory is restricted."
            }
        } Catch {
            Write-Warning "Failed to restrict SYSTEM access to the Print Spooler drivers directory because $($_.Exception.Message)"
        }
    }
}

if ((($RemotePrintPolicy -eq "2") -and ($SpoolerException -eq $false)) -or ($RemoveACL)) {
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
            Write-Output "Removed restriction of SYSTEM access to the Print Spooler drivers directory"
        } else {
            Write-Output "ACL removal not required; SYSTEM has access to the Print Spooler drivers directory"
        }
    } Catch {
        Write-Warning "Failed to remove SYSTEM access restriction on the Print Spooler drivers directory because $($_.Exception.Message)"
    }
}

if ($RestartSpooler) {
    if (Get-Service -Name Spooler | Where-Object Status -eq "Running") {
        if ((Get-Process spoolsv).StartTime -lt (Get-Date).AddHours(-24)) {
            # Only run if the Spooler service has been running for more than 24 hours.
            Write-Output "Restarting the Print Spooler service; Service has been running since $((Get-Process spoolsv).StartTime)"
            if (-not($WhatIf)) {
                Try {
                    Get-Service -Name Spooler | Stop-Service -Verbose -ErrorAction Stop
                    Get-Service -Name Spooler | Start-Service -Verbose -ErrorAction Stop
                } Catch {
                    Write-Warning "Failed to restart the Print Spooler service because $($_.Exception.Message)"
                }
            }
        } else {
            Write-Output "Print Spooler service is within the 1 day restart threshold; Service has been running since $((Get-Process spoolsv).StartTime)"
        }
    } else {
        Write-Output "Unable to restart because the Print Spooler service is not running"
    }
}

Stop-Transcript
