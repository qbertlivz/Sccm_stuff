<#
    .DESCRIPTION
        This script can be used to apply Windows customizations
	
    .PARAMETER File
        Specify an alternate name or location for the settings file. The script will search for Settings.ini in the script root by default
	
    .EXAMPLE
        Set-WindowsCustomizations.ps1    
        Set-WindowsCustomizations.ps1 -File C:\Temp\CustomSettings.ini
	
    .NOTES
        Created by: Jon Anderson (@ConfigJon)
        Updated 2023-05-03
        
    .CHANGELOG
        2019-07-11 - Fixed a syntax issue with the OneDriveSetup if statement
        2019-07-28 - Formatting changes, no new functionality
        2022-02-28 - Added logging. Updated syntax and formatting. Updated Edge customizations to work with new Edge
        2023-04-26 - Added detection logic for Windows OS version. Added more Windows 11 customizations. Formatting changes to make more use of functions
        2023-05-03 - Fixed issues with a few settings
#>

#Parameters ===================================================================================================================
<#
param
(
    [ValidateScript({
        if (!($_ | Test-Path))
        {
            throw "The specified file does not exist"
        }
        if (!($_ | Test-Path -PathType Leaf))
        {
            throw "The Path argument must be a file. Folder paths are not allowed."
        }
        if ($_ -notmatch "(\.ini)")
        {
            throw "The specified file must be a .ini file"
        }
        return $true 
    })]
    [parameter(Mandatory=$false)][System.IO.FileInfo]$File = "$ENV:WINDIR\Temp\Settings.ini"
)
#>

#Ensure the script is running using 64-bit PowerShell
if($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64")
{
    Try
	{
        &"$ENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -File $PSCOMMANDPATH
    }
    Catch
	{
        Throw "Failed to start $PSCOMMANDPATH"
    }
    Exit
}

$File = "$PSScriptRoot\Settings.ini"

#Functions ====================================================================================================================

Function Get-Settings
{
    [CmdletBinding()]
    param
	(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$File
    )
    Write-LogEntry -Value "`nImport settings from $File" -Severity 1 -Color Cyan
    Copy-Item -Path "$PSScriptRoot\Settings.ini" -Destination $FIle
    try
    {
        $Settings = Get-Content -Path $File
    }
    catch
    {
        Stop-Script -ErrorMessage "Failed to import settings from $File" -Exception $PSItem.Exception.Message
    }
    Write-LogEntry -Value "Successfully imported settings" -Severity 1 -Color Green
    return $Settings
}

Function Get-WindowsVersion
{
    $Caption = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption
    switch($Caption)
    {
        {$_ -match "Microsoft Windows 10"} {return "Windows 10"}
        {$_ -match "Microsoft Windows 11"} {return "Windows 11"}
        Default {return "Invalid OS"}
    }
}

Function Import-RegistryHive
{
    [CmdletBinding()]
    param
    (
        [String][parameter(Mandatory=$true)]$File,
        [String][parameter(Mandatory=$true)][ValidatePattern('^(HKLM\\|HKCU\\)[a-zA-Z0-9- _\\]+$')]$Key,
        [String][parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )
    $TestDrive = Get-PSDrive -Name $Name -ErrorAction SilentlyContinue
    if($NULL -ne $TestDrive)
    {
        Stop-Script -ErrorMessage "A drive with the name '$Name' already exists." -Exception [Management.Automation.SessionStateException]
    }
    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load $Key $File" -WindowStyle Hidden -PassThru -Wait
    if($Process.ExitCode)
    {
        Stop-Script -ErrorMessage "The registry hive '$File' failed to load. Verify the source path or target registry key." -Exception [Management.Automation.PSInvalidOperationException]
    }
    try
    {
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -ErrorAction Stop | Out-Null
    }
    catch
    {
        Stop-Script -ErrorMessage "A critical error creating drive '$Name' has caused the registy key '$Key' to be left loaded, this must be unloaded manually." -Exception [Management.Automation.PSInvalidOperationException]
    }
}

Function Remove-EdgeDesktopShortcut
{
    Write-LogEntry -Value "`nApply Setting: Edge Desktop Shortcut" -Severity 1 -Color Cyan
    $Shortcut = "$ENV:PUBLIC\Desktop\Microsoft Edge.lnk"
    if(Test-Path -Path $Shortcut)
    {
        $Error.Clear()
        try
        {
            Remove-Item -Path $Shortcut -Force
        }
        catch
        {
            Write-LogEntry -Value "Failed to delete $Shortcut" -Severity 3 -Color Red
        }
        if(!($Error))
        {
            Write-LogEntry -Value "Successfully deleted $Shortcut" -Severity 1 -Color Green
        }
    }
    else
    {
        Write-LogEntry -Value "Unable to find $Shortcut" -Severity 2 -Color Yellow
    }
}

Function Remove-OneDriveSetup
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$HiveName
    )
    Write-LogEntry -Value "`nApply Setting: Disable OneDrive Auto-Run" -Severity 1 -Color Cyan
    $Error.Clear()
    try
    {
        Remove-ItemProperty -Path "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Force -ErrorAction Stop
    }
    catch
    {
        Write-LogEntry -Value "Failed to delete OneDriveSetup from $($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Severity 3 -Color Red
    }
    if(!($Error))
    {
        Write-LogEntry -Value "Successfully deleted OneDriveSetup from $($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Severity 1 -Color Green
    }
}

Function Remove-RegistryHive
{
    [CmdletBinding()]
    param
    (
        [String][parameter(Mandatory=$true)][ValidatePattern('^[^;~/\\\.\:]+$')]$Name
    )
    $Drive = Get-PSDrive -Name $Name -ErrorAction Stop
    $Key = $Drive.Root
    Remove-PSDrive $Name -ErrorAction Stop
    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "unload $Key" -WindowStyle Hidden -PassThru -Wait
    if($Process.ExitCode)
    {
        New-PSDrive -Name $Name -PSProvider Registry -Root $Key -Scope Global -ErrorAction Stop | Out-Null
        Write-LogEntry -Value "The registry key '$Key' could not be unloaded, the key may still be in use." -Severity 3 -Color Red
    }
}

Function Set-Branding
{
    Write-LogEntry -Value "`nApply Setting: Set Branding" -Severity 1 -Color Cyan
    $Error.Clear()
    try
    {
        Start-Process -FilePath "$PSScriptRoot\Branding\Set-Branding.cmd"
    }
    catch
    {
        Write-LogEntry -Value "Failed to set branding" -Severity 3 -Color Red
    }
    if(!($Error))
    {
        Write-LogEntry -Value "Successfully set branding" -Severity 1 -Color Green
    }
}

Function Set-DefaultAppAssociations
{
    [CmdletBinding()]
    param
	(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$DefaultApps
    )
    Write-LogEntry -Value "`nApply Setting: Default Application Associations" -Severity 1 -Color Cyan
    if ($DefaultApps -like "*.xml")
    {
        $Error.Clear()
        try
        {
            Dism.exe /Online /Import-DefaultAppAssociations:"$PSScriptRoot\Configuration\$DefaultApps"
        }
        catch
        {
            Write-LogEntry -Value "Failed to set default application associations.`n$($PSItem.Exception.Message)" -Severity 3 -Color Red
        }
        if(!($Error))
        {
            Write-LogEntry -Value "Successfully set default application associations" -Severity 1 -Color Green
        }
    }
    else
    {
        Write-LogEntry -Value "$DefaultApps is not an xml file. Skipping this setting" -Severity 3 -Color Red
    }
}

Function Set-DefaultStartLayoutBin
{
    [CmdletBinding()]
    param
	(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$StartLayout
    )
    Write-LogEntry -Value "`nApply Setting: Default Start Menu Layout Windows 11" -Severity 1 -Color Cyan
    $StartLayoutPath = "$ENV:SystemDrive\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState"
    New-Item -Path $StartLayoutPath -ItemType Directory
    Copy-Item -Path "$PSScriptRoot\Configuration\$StartLayout" -Destination "$StartLayoutPath\$StartLayout" -Force
}

Function Set-DefaultStartLayoutXml
{
    [CmdletBinding()]
    param
	(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$StartLayout
    )
    Write-LogEntry -Value "`nApply Setting: Default Start Menu and Taskbar Layout" -Severity 1 -Color Cyan
    if($StartLayout -like "*.xml")
    {
        $Error.Clear()
        try
        {
            Import-StartLayout -LayoutPath "$PSScriptRoot\Configuration\$StartLayout" -MountPath "$Env:SystemDrive\"
        }
        catch
        {
            Write-LogEntry -Value "Failed to set the default Start Menu and Taskbar layout.`n$($PSItem.Exception.Message)" -Severity 3 -Color Red
        }
        if(!($Error))
        {
            Write-LogEntry -Value "Successfully set the default Start Menu and Taskbar layout" -Severity 1 -Color Green
        }
    }
    else
    {
        Write-LogEntry -Value "$StartLayout is not an xml file. Skipping this setting" -Severity 3 -Color Red
    }
}

Function Set-DynamicTime
{
    Write-LogEntry -Value "`nApply Setting: Enable dynamic time via location services" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -PropertyType String -Value "Allow"
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -PropertyType DWord -Value 1
	Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
}

Function Set-RegistryValue
{
    [CmdletBinding()]
    param
	(   
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$RegKey,
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Name,
        [String][parameter(Mandatory=$true)][ValidateSet('String','ExpandString','Binary','DWord','MultiString','Qword','Unknown')]$PropertyType,
        [String][parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value
    )
    if(!(Test-Path $RegKey))
    {
        try
        {
            New-Item -Path $RegKey -Force | Out-Null
        }
        catch
        {
            Write-LogEntry -Value "Failed to create $RegKey`n$($PSItem.Exception.Message)" -Severity 3 -Color Red
        }
    }
    try
    {
        New-ItemProperty -Path $RegKey -Name $Name -PropertyType $PropertyType -Value $Value -Force | Out-Null
    }
    catch
    {
        Write-LogEntry -Value "Failed to set $RegKey\$Name to $Value`n$($PSItem.Exception.Message)" -Severity 3 -Color Red
    }
    $KeyCheck = Get-ItemProperty $RegKey
    if($KeyCheck.$Name -eq $Value)
    {
        Write-LogEntry -Value "Successfully set $RegKey\$Name to $Value" -Severity 1 -Color Green
    }
    else
    {
        Write-LogEntry -Value "Failed to set $RegKey\$Name to $Value`n$($PSItem.Exception.Message)" -Severity 3 -Color Red
    }
}

Function Stop-Script
{
    [CmdletBinding()]
    param
	(
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][String]$ErrorMessage,
        [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][String]$Exception
    )
    Write-LogEntry -Value $ErrorMessage -Severity 3 -Color Red
    if($Exception)
    {
        Write-LogEntry -Value "Exception Message: $Exception" -Severity 3 -Color Red
    }
    exit
}

Function Write-LogEntry
{
    [CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")][ValidateNotNullOrEmpty()][string]$Value,
		[parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")][ValidateNotNullOrEmpty()][ValidateSet("1", "2", "3")][string]$Severity,
        [Parameter(Mandatory = $true)][ValidateSet("Cyan","White","Green","Yellow","Red", IgnoreCase = $true)][String]$Color,
		[parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")][ValidateNotNullOrEmpty()][string]$FileName = "Set-WindowsCustomizations.log"
	)
    $LogsDirectory = "$ENV:ALLUSERSPROFILE\Microsoft\IntuneManagementExtension\Logs"
	$LogFilePath = Join-Path -Path $LogsDirectory -ChildPath $FileName
	if(-not(Test-Path -Path 'variable:global:TimezoneBias'))
	{
		[string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
		if($TimezoneBias -match "^-")
		{
			$TimezoneBias = $TimezoneBias.Replace('-', '+')
		}
		else
		{
			$TimezoneBias = '-' + $TimezoneBias
		}
	}
	$Time = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)	
	$Date = (Get-Date -Format "MM-dd-yyyy")
	$Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""Set-WindowsCustomizations"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
	try
	{
		Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
	}
	catch [System.Exception]
	{
		Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
	}
    Write-Host -ForegroundColor $Color -Object $Value
}

# Main program =================================================================================================================

Write-LogEntry -Value "START - Windows Customization Script" -Severity 1 -Color Cyan

# Check the Windows OS version
$WindowsVersion = Get-WindowsVersion
Write-LogEntry -Value "The installed Windows version is $WindowsVersion" -Severity 1 -Color White

# Read data from the settings file
$Settings = Get-Settings -File $File

# Create variables for each line in the settings file
Write-LogEntry -Value "`nCreate and set variables" -Severity 1 -Color Cyan
ForEach($Setting in $Settings)
{
    if(!($Setting.StartsWith('#')))
    {
        try
        {
            $Variable = $Setting.Split('=')
            Write-LogEntry -Value "Creating variable $($Variable[0].Trim()) with value $($Variable[1].Trim())" -Severity 1 -Color White
            New-Variable -Name $Variable[0].Trim() -Value $Variable[1].Trim() -Scope "Global" -Force
        }
        catch
        {
            Stop-Script -ErrorMessage "Failed to import $Setting" -Exception $PSItem.Exception.Message
        }
    }
}
Write-LogEntry -Value "Successfully created all variables" -Severity 1 -Color Green

# Import Default Application Associations
if($DefaultApps10 -or $DefaultApps11)
{
    if($WindowsVersion -eq "Windows 10")
    {
        Set-DefaultAppAssociations -DefaultApps $DefaultApps10
    }
    if($WindowsVersion -eq "Windows 11")
    {
        Set-DefaultAppAssociations -DefaultApps $DefaultApps11
    }
}

# Import Default Start Menu and Taskbar Layout
if($StartLayout10 -or $TaskbarLayout11)
{
    if($WindowsVersion -eq "Windows 10")
    {
        Set-DefaultStartLayoutXml -StartLayout $StartLayout10
    }
    if($WindowsVersion -eq "Windows 11")
    {
        Set-DefaultStartLayoutXml -StartLayout $TaskbarLayout11
    }
}
if($StartLayout11)
{
    if($WindowsVersion -eq "Windows 11")
    {
        Set-DefaultStartLayoutBin -StartLayout $StartLayout11
    }
}

# Set the desktop background and lock screen image
if($SetBranding -eq 1)
{
    Set-Branding
}

# Set dynamic time via location services
if($DynamicTime -eq 1)
{
    Set-DynamicTime
}

# Run HKLM Registry Customizations
if($NetworkNotification)
{
    Write-LogEntry -Value "`nApply Setting: New Network Notification" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" -Name '(Default)' -PropertyType String -Value "Placeholder"
}
if($EdgeFirstRun)
{
    Write-LogEntry -Value "`nApply Setting: Edge First Run Page" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -PropertyType DWord -Value $EdgeFirstRun
}
if($EdgeDesktopShortcut)
{
    Remove-EdgeDesktopShortcut
}
if($Cortana)
{
    Write-LogEntry -Value "`nApply Setting: Cortana" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value $Cortana
}
if($OOBECortana)
{
    Write-LogEntry -Value "`nApply Setting: OOBE Cortana" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" -Name "DisableVoice" -PropertyType DWord -Value $OOBECortana
}
if($FirstLogonAnimation)
{
    Write-LogEntry -Value "`nApply Setting: First Logon Animation" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value $FirstLogonAnimation
}
if($ConsumerFeatures)
{
    Write-LogEntry -Value "`nApply Setting: Windows Consumer Features" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value $ConsumerFeatures
}
if($WindowsTips)
{
    Write-LogEntry -Value "`nApply Setting: Windows Tips" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -PropertyType DWord -Value $WindowsTips
}
if($FileExplorerView)
{
    Write-LogEntry -Value "`nApply Setting: Default File Explorer View" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -PropertyType DWord -Value $FileExplorerView
}
if($RunAsUserStart)
{
    Write-LogEntry -Value "`nApply Setting: Show Run as User in Start Menu" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "ShowRunasDifferentuserinStart" -PropertyType DWord -Value $RunAsUserStart
}
if($FastStartup)
{
    Write-LogEntry -Value "`nApply Setting: Fast Startup" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -PropertyType DWord -Value $FastStartup
}

# Load the Default User registry hive
$HiveName = "DefaultUserHive"
Write-LogEntry -Value "`nImport the Default User registry hive" -Severity 1 -Color Cyan
Import-RegistryHive -File 'C:\Users\Default\NTUSER.DAT' -Key 'HKLM\DefaultUser' -Name $HiveName

# Run Default User Registry Customizations
if($DefenderPrompt)
{
    Write-LogEntry -Value "`nApply Setting: Disable Defender User Prompt" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows Defender" -Name "UifirstRun" -PropertyType DWord -Value $DefenderPrompt
}
if($OneDriveSetup -eq "Delete")
{
    Remove-OneDriveSetup -HiveName $HiveName
}
if($InkWorkspaceIcon)
{
    Write-LogEntry -Value "`nApply Setting: Ink Workspace Icon" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -PropertyType DWord -Value $InkWorkspaceIcon
}
if($TouchKeyboardIcon)
{
    Write-LogEntry -Value "`nApply Setting: Touch Keyboard Icon" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\TabletTip\1.7" -Name "TipbandDesiredVisibility" -PropertyType DWord -Value $TouchKeyboardIcon
}
if($SearchBox)
{
    Write-LogEntry -Value "`nApply Setting: Search Box Windows" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWord -Value $SearchBox
}
if($ThisPCDesktop)
{
    Write-LogEntry -Value "`nApply Setting: This PC Desktop Shortcut" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -PropertyType DWord -Value $ThisPCDesktop
}
if($UserFilesDesktop)
{
    Write-LogEntry -Value "`nApply Setting: User Files Desktop Shortcut" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -PropertyType DWord -Value $UserFilesDesktop
}
if($NetworkDesktop)
{
    Write-LogEntry -Value "`nApply Setting: Network Desktop Shortcut" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -PropertyType DWord -Value $NetworkDesktop
}
if($RecycleBinDesktop)
{
    Write-LogEntry -Value "`nApply Setting: Recycle Bin Desktop Shortcut" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -PropertyType DWord -Value $RecycleBinDesktop
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -PropertyType DWord -Value $RecycleBinDesktop
}
if($ControlPanelDesktop)
{
    Write-LogEntry -Value "`nApply Setting: Control Panel Desktop Shortcut" -Severity 1 -Color Cyan
    Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -PropertyType DWord -Value $ControlPanelDesktop
}

# Windows 10 Specific Customizations
if($WindowsVersion -eq "Windows 10")
{
    if($NewsAndInterests)
    {
        Write-LogEntry -Value "`nApply Setting: News and Interests Icon" -Severity 1 -Color Cyan
        Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -PropertyType DWord -Value $NewsAndInterests
        Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" -Name "IsFeedsAvailable" -PropertyType DWord -Value 0
        Set-RegistryValue -RegKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -PropertyType DWord -Value 0
    }
    if($PeopleIcon)
    {
        Write-LogEntry -Value "`nApply Setting: People Icon" -Severity 1 -Color Cyan
        Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -PropertyType DWord -Value $PeopleIcon
    }
    if($TaskViewIcon)
    {
        Write-LogEntry -Value "`nApply Setting: Task View Icon" -Severity 1 -Color Cyan
        Set-RegistryValue -RegKey "$($HiveName):\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -PropertyType DWord -Value $TaskViewIcon
    }
}

# Windows 11 Specific Customizations
if($WindowsVersion -eq "Windows 11")
{
	if($TaskbarAlignment)
	{
		Write-LogEntry -Value "`nApply Setting: Windows 11 Taskbar Alignment" -Severity 1 -Color Cyan
		Set-RegistryValue -RegKey "$($HiveName):\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -PropertyType DWord -Value $TaskbarAlignment
	}
	if($TaskbarSize)
	{
		Write-LogEntry -Value "`nApply Setting: Windows 11 Taskbar Size" -Severity 1 -Color Cyan
		Set-RegistryValue -RegKey "$($HiveName):\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSi" -PropertyType DWord -Value $TaskbarSize
	}
	if($ChatIcon)
	{
		Write-LogEntry -Value "`nApply Setting: Windows 11 Chat Icon" -Severity 1 -Color Cyan
		Set-RegistryValue -RegKey "$($HiveName):\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -PropertyType DWord -Value $ChatIcon
        $TeamsApp = Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq "MicrosoftTeams"
        if($TeamsApp)
        {
            Write-LogEntry -Value "`nRemoving the built-in Microsoft Teams app" -Severity 1 -Color Cyan
            Remove-AppxProvisionedPackage -Online -PackageName $TeamsApp.PackageName
        }
	}
	if($WidgetsIcon)
	{
		Write-LogEntry -Value "`nApply Setting: Windows 11 Widgets Icon" -Severity 1 -Color Cyan
		Set-RegistryValue -RegKey "$($HiveName):\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -PropertyType DWord -Value $WidgetsIcon
	}
    if($TaskViewIcon11)
	{
		Write-LogEntry -Value "`nApply Setting: Windows 11 TaskView Icon" -Severity 1 -Color Cyan
		Set-RegistryValue -RegKey "$($HiveName):\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -PropertyType DWord -Value $TaskViewIcon11
	}
}

# Unload the Default User registry hive
Write-LogEntry -Value "`nUnload the Default user registry hive" -Severity 1 -Color Cyan
$Count = 0
while($true)
{
    try
    {
        $Count++
        Remove-RegistryHive -Name $HiveName
        Write-Output 'Remove-RegistryHive succeeded. NTUSER.DAT updated successfully'
        Write-LogEntry -Value "Successfully unloaded the Default user registry hive. NTUSER.DAT updated successfully" -Severity 1 -Color Green
        break
    }
    catch
    {
        if ($Count -eq 3)
        {
            throw
        }
        Start-Sleep -Milliseconds 100
        [gc]::Collect()
    }
}

Write-LogEntry -Value "`nEND - Windows Customization Script" -Severity 1 -Color Cyan