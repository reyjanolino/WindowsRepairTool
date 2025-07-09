[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") | Out-Null

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class DpiSupport {
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
}
"@
[DpiSupport]::SetProcessDPIAware()

function Ensure-Admin {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        [System.Windows.Forms.MessageBox]::Show("This tool must be run as Administrator.", "Admin Rights Required", 'OK', 'Error')
        exit
    }
}

Ensure-Admin

$form = New-Object System.Windows.Forms.Form
$form.Text = "RJ Windows Repair Tool"
$form.Size = New-Object System.Drawing.Size(720, 700)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
$form.ForeColor = [System.Drawing.Color]::White
$form.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Regular)

$accentColor = [System.Drawing.Color]::FromArgb(37, 99, 235) # Windows 11 accent blue

$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Size = New-Object System.Drawing.Size(680, 440)
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Appearance = 'Normal'
$tabControl.DrawMode = 'OwnerDrawFixed'
$tabControl.Add_DrawItem({
    param ($sender, $e)

    $g = $e.Graphics
    $tabPage = $sender.TabPages[$e.Index]
    $tabBounds = $sender.GetTabRect($e.Index)

    # Define style
    $isSelected = $e.Index -eq $sender.SelectedIndex

    $font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $bgColor = if ($isSelected) { [System.Drawing.Color]::LightSkyBlue } else { [System.Drawing.Color]::WhiteSmoke }
    $textColor = [System.Drawing.Color]::Black

    $g.FillRectangle((New-Object Drawing.SolidBrush $bgColor), $tabBounds)
    $textSize = $g.MeasureString($tabPage.Text, $font)
    $textX = $tabBounds.X + ($tabBounds.Width - $textSize.Width) / 2
    $textY = $tabBounds.Y + ($tabBounds.Height - $textSize.Height) / 2

    $g.DrawString($tabPage.Text, $font, (New-Object Drawing.SolidBrush $textColor), $textX, $textY)
})


$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Multiline = $true
$logBox.ScrollBars = "Vertical"
$logBox.Size = New-Object System.Drawing.Size(680, 120)
$logBox.Location = New-Object System.Drawing.Point(10, 470)
$logBox.ReadOnly = $true
$logBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$logBox.BackColor = [System.Drawing.Color]::FromArgb(24,24,24)
$logBox.ForeColor = [System.Drawing.Color]::White

function Write-Log($msg) {
    $timestamp = (Get-Date).ToString("HH:mm:ss")
    $entry = "[$timestamp] $msg"
    $logBox.AppendText("$entry`r`n")
    Add-Content -Path "$PSScriptRoot\rj_toolkit_log.txt" -Value $entry
}

$tab1 = New-Object System.Windows.Forms.TabPage
$tab1.Text = "System Repair"
$tab1.BackColor = $form.BackColor
$tab1.ForeColor = $form.ForeColor

$tab2 = New-Object System.Windows.Forms.TabPage
$tab2.Text = "Network Tools"
$tab2.BackColor = $form.BackColor
$tab2.ForeColor = $form.ForeColor

$tab3 = New-Object System.Windows.Forms.TabPage
$tab3.Text = "Extras"
$tab3.BackColor = $form.BackColor
$tab3.ForeColor = $form.ForeColor

#  System Info Tab
$tabSystemInfo = New-Object System.Windows.Forms.TabPage
$tabSystemInfo.Text = "System Info"
$tabSystemInfo.BackColor = $form.BackColor
$tabSystemInfo.ForeColor = $form.ForeColor

$txtSystemInfo = New-Object System.Windows.Forms.RichTextBox
$txtSystemInfo.Dock = 'Fill'
$txtSystemInfo.ReadOnly = $true
$txtSystemInfo.Multiline = $true
$txtSystemInfo.ScrollBars = "Vertical"
$txtSystemInfo.Font = 'Consolas, 11'
$txtSystemInfo.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
$txtSystemInfo.ForeColor = [System.Drawing.Color]::White
$txtSystemInfo.BorderStyle = 'None'
$txtSystemInfo.SelectionIndent = 30
$pcName = $env:COMPUTERNAME
$txtSystemInfo.AppendText("`r`n") # Bottom spacing

$tabSystemInfo.Controls.Add($txtSystemInfo)

function Show-SystemInfo {
    $cpu = Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name
    $ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    $gpu = Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name -First 1
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $uptime = ((Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime).ToString("dd\.hh\:mm\:ss")

    $diskInfo = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    $label = if ($_.VolumeName) { $_.VolumeName } else { "Unnamed" }
    $sizeGB = "{0:N1}" -f ($_.Size / 1GB)
    $freeGB = "{0:N1}" -f ($_.FreeSpace / 1GB)
    "$($_.DeviceID) [$label] : $freeGB GB free of $sizeGB GB"
}

    $info = @"
	
PC NAME : $pcName
CPU     : $cpu
RAM     : ${ram} GB
GPU     : $gpu
OS      : $os
Uptime  : $uptime

Drives  :
$($diskInfo -join "`r`n")
"@

    $txtSystemInfo.Text = $info
}

# Registry Manager Tab
$registryManagerTab = New-Object System.Windows.Forms.TabPage
$registryManagerTab.Text = "Registry Manager"
$registryManagerTab.BackColor = $form.BackColor
$registryManagerTab.ForeColor = $form.ForeColor

# Hive Dropdown
$comboHive = New-Object System.Windows.Forms.ComboBox
$comboHive.Location = New-Object System.Drawing.Point(20, 20)
$comboHive.Size = New-Object System.Drawing.Size(200, 25)
$comboHive.Items.AddRange(@(
    "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG"
))
$comboHive.SelectedIndex = 0
$registryManagerTab.Controls.Add($comboHive)

# Create Backup Folder if not exist
$backupFolder = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "Reg_Backup"
if (-not (Test-Path $backupFolder)) {
    New-Item -Path $backupFolder -ItemType Directory | Out-Null
}

# Backup Selected Hive
$btnBackupSelected = New-Object System.Windows.Forms.Button
$btnBackupSelected.Location = New-Object System.Drawing.Point(20, 60)
$btnBackupSelected.Size = New-Object System.Drawing.Size(200, 30)
$btnBackupSelected.Text = "Backup Selected Hive"
$btnBackupSelected.Add_Click({
    $selectedHive = $comboHive.SelectedItem
    $safeName = $selectedHive -replace "HKEY_", "HK"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFile = Join-Path $backupFolder "$safeName-$timestamp.reg"
    try {
        reg export "$selectedHive" "$backupFile" /y | Out-Null
        Write-Log "Backed up $selectedHive to $backupFile"
    } catch {
        Write-Log "Error backing up )"
    }
})
$registryManagerTab.Controls.Add($btnBackupSelected)

$registryManagerTab.Controls.Add($btnBackupAll)

# Restore Registry
$btnRestoreReg = New-Object System.Windows.Forms.Button
$btnRestoreReg.Location = New-Object System.Drawing.Point(250, 60)
$btnRestoreReg.Size = New-Object System.Drawing.Size(200, 30)
$btnRestoreReg.Text = "Restore Registry"
$btnRestoreReg.Add_Click({
    $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $fileDialog.InitialDirectory = $backupFolder
    $fileDialog.Filter = "Registry Files (*.reg)|*.reg"
    $fileDialog.Title = "Select Registry Backup to Restore"

    if ($fileDialog.ShowDialog() -eq "OK") {
        $regFile = $fileDialog.FileName
        try {
            reg import "$regFile" | Out-Null
            Write-Log "Successfully restored from $regFile"
        } catch {
            Write-Log "Failed to restore registry: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Restore cancelled by user."
    }
})
$registryManagerTab.Controls.Add($btnRestoreReg)


# Export Button
$btnExport = New-Object Windows.Forms.Button
$btnExport.Text = "Export Entire Registry"
$btnExport.Size = '200,30'
$btnExport.Location = '20,110'
$registryManagerTab.Controls.Add($btnExport)

# Import Button
$btnImport = New-Object Windows.Forms.Button
$btnImport.Text = "Import .reg File"
$btnImport.Size = '200,30'
$btnImport.Location = '250,110'
$form.Controls.Add($btnImport)
$registryManagerTab.Controls.Add($btnImport)

# Export Function
$btnExport.Add_Click({
    # Create timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
    $defaultName = "FullRegistryBackup_$timestamp.reg"

    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "Registry Files (*.reg)|*.reg"
    $saveDialog.Title = "Export Entire Registry"
    $saveDialog.FileName = $defaultName

    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            Start-Process -FilePath "regedit.exe" -ArgumentList "/e `"$($saveDialog.FileName)`"" -Wait -NoNewWindow
            [System.Windows.Forms.MessageBox]::Show("Registry successfully exported to:`n$($saveDialog.FileName)", "Success", "OK", "Information")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $_", "Error", "OK", "Error")
        }
    }
})

# Import Function
$btnImport.Add_Click({
    $openDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openDialog.Filter = "Registry Files (*.reg)|*.reg"
    $openDialog.Title = "Import Registry File"

    if ($openDialog.ShowDialog() -eq "OK") {
        $regFile = $openDialog.FileName
        $confirm = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to import:`n$regFile", "Confirm Import", "YesNo", "Question")
        if ($confirm -eq "Yes") {
            try {
                Start-Process -FilePath "regedit.exe" -ArgumentList "/s `"$regFile`"" -Verb RunAs -Wait
                [System.Windows.Forms.MessageBox]::Show("Registry successfully imported.", "Success", "OK", "Information")
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Import failed: $_", "Error", "OK", "Error")
            }
        }
    }
})



# Add Registry Manager tab to tab control
$tabControl.TabPages.AddRange(@($tab1, $tab2, $registryManagerTab, $tab3, $tabSystemInfo))
$form.Controls.Add($tabControl)
$form.Controls.Add($logBox)

$tabControl.Add_SelectedIndexChanged({
    if ($tabControl.SelectedTab -eq $tabSystemInfo) {
        Show-SystemInfo
    }
})


# Creating checkbox
function Create-Checkbox($text, $x, $y) {
    $chk = New-Object System.Windows.Forms.CheckBox
    $chk.Text = $text
    $chk.Location = New-Object System.Drawing.Point($x, $y)
    $chk.ForeColor = [System.Drawing.Color]::White
    $chk.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Regular)
    $chk.AutoSize = $true
    return $chk
}

$chkRestore = Create-Checkbox "Create Restore Point" 10 20
$chkCleanTemp = Create-Checkbox "Clear Temp / Prefetch Files" 10 50
$chkSFC = Create-Checkbox "Run SFC /scannow" 10 80
$chkDISM = Create-Checkbox "Run DISM /RestoreHealth" 10 110
$chkDISMExpDrv = Create-Checkbox "Export Device Drivers" 10 140
$chkExpBCD = Create-Checkbox "Export BCD Backup" 10 170
$chkImpBCD = Create-Checkbox "Restore BCD" 10 200

	# Make them mutually exclusive
	$chkExpBCD.Add_CheckedChanged({
		if ($chkExpBCD.Checked) { $chkImpBCD.Checked = $false }
	})
	$chkImpBCD.Add_CheckedChanged({
		if ($chkImpBCD.Checked) { $chkExpBCD.Checked = $false }
	})

$tab1.Controls.AddRange(@($chkRestore, $chkCleanTemp, $chkSFC, $chkDISM, $chkDISMExpDrv, $chkExpBCD, $chkImpBCD))

$chkRebBack = Create-Checkbox "Enable Registry Backup (RegBack)" 20 170
$registryManagerTab.Controls.Add($chkRebBack)

$chkResetNet = Create-Checkbox "Reset Winsock & IP Stack" 10 120
$chkFlushDNS = Create-Checkbox "Flush DNS" 10 150

$adapterLabel = New-Object System.Windows.Forms.Label
$adapterLabel.Text = "Select Active Adapter:"
$adapterLabel.ForeColor = [System.Drawing.Color]::White
$adapterLabel.Location = New-Object System.Drawing.Point(10, 20)
$adapterLabel.AutoSize = $true

$cmbAdapters = New-Object System.Windows.Forms.ComboBox
$cmbAdapters.Location = New-Object System.Drawing.Point(160, 22)
$cmbAdapters.Size = New-Object System.Drawing.Size(200, 20)
$cmbAdapters.DropDownStyle = 'DropDownList'

function Refresh-NetworkAdapters {
    param(
        [bool]$Log = $false
    )

    $cmbAdapters.Items.Clear()
    
    $adapters = Get-NetAdapter | Where-Object {
        $_.Status -eq 'Up' -and
        $_.HardwareInterface -eq $true -and
        $_.InterfaceDescription -notmatch 'vmware|virtual'
    }

    foreach ($adapter in $adapters) {
        $cmbAdapters.Items.Add($adapter.Name) | Out-Null
    }

    # Auto-select first adapter if available
    if ($cmbAdapters.Items.Count -gt 0) {
        $cmbAdapters.SelectedIndex = 0
    }

    if ($Log) {
        $time = Get-Date -Format "HH:mm:ss"
        Write-Log " Adapter list refreshed on [$time]."
    }
}

Refresh-NetworkAdapters

$btnRefreshAdapters = New-Object System.Windows.Forms.Button
$btnRefreshAdapters.Text = "Refresh Adapters"
$btnRefreshAdapters.Size = '120,25'
$btnRefreshAdapters.Location = New-Object System.Drawing.Point(370, 22)
$btnRefreshAdapters.BackColor = $accentColor
$btnRefreshAdapters.ForeColor = [System.Drawing.Color]::White
$btnRefreshAdapters.FlatStyle = 'Flat'
$btnRefreshAdapters.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnRefreshAdapters.FlatAppearance.BorderSize = 0
$btnRefreshAdapters.Add_Click({ Refresh-NetworkAdapters -Log $true})

$chkSetDNS = Create-Checkbox "Set DNS" 10 55
$dnsLabel = New-Object System.Windows.Forms.Label
$dnsLabel.Text = "Choose DNS Server:"
$dnsLabel.ForeColor = [System.Drawing.Color]::White
$dnsLabel.Location = New-Object System.Drawing.Point(30, 80)
$dnsLabel.AutoSize = $true

$dnsCombo = New-Object System.Windows.Forms.ComboBox
$dnsCombo.Location = New-Object System.Drawing.Point(160, 80)
$dnsCombo.Size = New-Object System.Drawing.Size(200, 20)
$dnsCombo.DropDownStyle = 'DropDownList'
$dnsCombo.Items.AddRange(@("Cloudflare (1.1.1.1)", "Google (8.8.8.8)", "OpenDNS (208.67.222.222)"))

$chkEncryptedDNS = Create-Checkbox "Enable Encrypted DNS (DoH)" 10 180
$chkPing = Create-Checkbox "Test Internet Connectivity" 10 210

$tab2.Controls.AddRange(@($chkResetNet, $chkFlushDNS, $adapterLabel, $cmbAdapters, $btnRefreshAdapters, $chkSetDNS, $dnsLabel, $dnsCombo, $chkEncryptedDNS, $chkPing))

# Activate Windows Button
$btnActwin = New-Object System.Windows.Forms.Button
$btnActwin.Location = New-Object System.Drawing.Point(20, 20)
$btnActwin.Size = New-Object System.Drawing.Size(200, 30)
$btnActwin.Text = "Activate Windows"
$btnActwin.Add_Click({
    try {
		Write-Log "loading..."
        irm https://get.activated.win | iex
        Write-Log "Activate Windows Tool is ready"
    } catch {
		# irm https://massgrave.dev/get | iex
        Write-Log "Error loading up, trying next server"
    }
})

# Windows Enhancement using Registry
$btnEnhance = New-Object System.Windows.Forms.Button
$btnEnhance.Location = New-Object System.Drawing.Point(20, 60)
$btnEnhance.Size = New-Object System.Drawing.Size(200, 30)
$btnEnhance.Text = "Enhance Windows"
$btnEnhance.Add_Click({
  
        try {

		function Set-RegistryValue {
	param (
		[string]$Path,
		[string]$Name,
		[Object]$Value,
		[Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::DWord
	)
	if (-not (Test-Path $Path)) {
		New-Item -Path $Path -Force | Out-Null
	}
	New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
		}
		
		Write-Host "Updating Privacy settings..." -ForegroundColor Green
		Write-Host "Disable Telemetry"
		Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
		Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0

		Write-Host "Disable Feedback Requests"
		Set-RegistryValue "HKCU:\Software\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0
		Set-RegistryValue "HKCU:\Software\Microsoft\Siuf\Rules" "PeriodInDays" 0

		Write-Host "Disable Advertising ID"
		Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0

		Write-Host "Disable Cortana"
		Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0

		Write-Host "Disable Location Tracking"
		Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1

		Write-Host "Disable App Access to Location, Calendar, Contacts"
		Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny" ([Microsoft.Win32.RegistryValueKind]::String)
		Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" "Value" "Deny" ([Microsoft.Win32.RegistryValueKind]::String)
		Set-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\calendar" "Value" "Deny" ([Microsoft.Win32.RegistryValueKind]::String)

		Write-Host "Disable SmartScreen for Apps"
		Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 0

		Write-Host "Disable Windows Tips and Suggestions"
		Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0
		Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0
		Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338393Enabled" 0
		Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353694Enabled" 0

		Write-Host "Disable Telemetry Services"
		Get-Service DiagTrack, dmwappushservice -ErrorAction SilentlyContinue | ForEach-Object {
			Set-Service -Name $_.Name -StartupType Disabled
			Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
		}

		Write-Host "Disable Automatic Driver Updates via Windows Update"
		Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ExcludeWUDriversInQualityUpdate" 1

		Write-Host "Disable Microsoft Consumer Experience (preinstalled apps)"
		Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerFeatures" 1

		Write-Host "Disable Activity History"
		Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
		Set-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0

		Write-Host "Disable Background Apps Globally"
		Set-RegistryValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1

		Write-Host "Privacy settings have been applied successfully." -ForegroundColor Green

		# Define helper function for setting registry DWORD
		function Set-RegistryDwordValue($path, $name, $value) {
			New-Item -Path $path -Force | Out-Null
			Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord
		}

		Write-Host "Updating current user settings..." -ForegroundColor Green
		Write-Host "Disable Content Delivery settings"
		$cdmPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
		$dwordValues = @(
			"ContentDeliveryAllowed", "FeatureManagementEnabled", "OEMPreInstalledAppsEnabled",
			"PreInstalledAppsEnabled", "PreInstalledAppsEverEnabled", "SilentInstalledAppsEnabled",
			"RotatingLockScreenEnabled", "RotatingLockScreenOverlayEnabled", "SoftLandingEnabled",
			"SubscribedContentEnabled", "SubscribedContent-310093Enabled", "SubscribedContent-338387Enabled",
			"SubscribedContent-338388Enabled", "SubscribedContent-338389Enabled", "SubscribedContent-338393Enabled",
			"SubscribedContent-353698Enabled", "SubscribedContent-353694Enabled", "SubscribedContent-353696Enabled",
			"SystemPaneSuggestionsEnabled"
		)
		foreach ($name in $dwordValues) {
			Set-RegistryDwordValue -path $cdmPath -name $name -value 0
		}

		Write-Host "Delete Subscriptions and SuggestedApps keys"
		Remove-Item -Path "$cdmPath\Subscriptions" -Recurse -Force -ErrorAction SilentlyContinue
		Remove-Item -Path "$cdmPath\SuggestedApps" -Recurse -Force -ErrorAction SilentlyContinue

		Write-Host "Privacy Settings"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -name "TailoredExperiencesWithDiagnosticDataEnabled" -value 0
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -name "IsMiEnabled" -value 0

		Write-Host "Speech Privacy"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -name "HasAccepted" -value 0

		Write-Host "Removes Copilot"
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce" -Force | Out-Null
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce" -Name "UninstallCopilot" -Value ""
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -name "TurnOffWindowsCopilot" -value 1

		Write-Host "Removes Store Banner in Notepad"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Notepad" -name "ShowStoreBanner" -value 0

		Write-Host "Removes OneDrive from Startup"
		Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -ErrorAction SilentlyContinue

		Write-Host "Aligns Taskbar to the Left"
		Set-RegistryDwordValue -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "TaskbarAl" -value 0

		Write-Host "Hides Search Icon on Taskbar"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -name "SearchboxTaskbarMode" -value 0

		Write-Host "Disables Recently Added Apps & Start Menu Recommendations"
		Set-RegistryDwordValue -path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -name "HideRecentlyAddedApps" -value 1
		Set-RegistryDwordValue -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "Start_IrisRecommendations" -value 0

		Write-Host "Removes People from Taskbar"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -name "PeopleBand" -value 0

		Write-Host "Hides Task View Button"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "ShowTaskViewButton" -value 0

		Write-Host "Disables News and Interests"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" -name "ShellFeedsTaskbarViewMode" -value 2
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" -name "ShellFeedsEnabled" -value 0
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -name "EnableFeeds" -value 0

		Write-Host "Disables Account Sync"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -name "SettingSyncEnabled" -value 0

		Write-Host "Disables Location Services"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -name "LocationServicesEnabled" -value 0

		Write-Host "Disables Input Personalization"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -name "AcceptedPrivacyPolicy" -value 0
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" -name "RestrictImplicitTextCollection" -value 1
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" -name "RestrictImplicitInkCollection" -value 1

		Write-Host "Disables Feedback Sampling"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" -name "AutoSample" -value 0
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" -name "ServiceEnabled" -value 0

		Write-Host "Disables Recent Documents"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "Start_TrackDocs" -value 0

		Write-Host "Disables Language List Web Content"
		Set-RegistryDwordValue -path "HKCU:\Control Panel\International\User Profile" -name "HttpAcceptLanguageOptOut" -value 1

		Write-Host "Disables App Launch Tracking"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name "Start_TrackProgs" -value 0

		Write-Host "Disables Background Apps"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -name "GlobalUserDisabled" -value 1

		Write-Host "Disables App Diagnostics"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppDiagnostics" -name "AppDiagnosticsEnabled" -value 0

		Write-Host "Disables Delivery Optimization"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -name "DODownloadMode" -value 0

		Write-Host "Disables Tablet Mode"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -name "TabletMode" -value 0

		Write-Host "Disables Use Sign-In Info"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication" -name "UseSignInInfo" -value 0

		Write-Host "Disables Maps Auto Download"
		Set-RegistryDwordValue -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Maps" -name "AutoDownload" -value 0

		Write-Host "Disables Telemetry and Ads"
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Type DWord
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWord

		Write-Host "Enable Enthusiast Mode in Operation Status Manager"
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Value 1 -Type DWord

		Write-Host "Set File Explorer to Open This PC"
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 -Type DWord

		Write-Host "Auto End Tasks on Shutdown"
		Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value 1 -Type DWord

		Write-Host "Set Mouse Hover Time"
		Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Value "400" -Type String

		Write-Host "Hide Meet Now Button"
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1 -Type DWord

		Write-Host "Disable Second Out-Of-Box Experience"
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -Type DWord

		Write-Host "Enable End Task with Right Click"
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDeveloperSettings" -Value 1 -Type DWord
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarEndTask" -Value 1 -Type DWord

		Write-Host "Classic Right-Click Menu for Windows 11"
		New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null
		New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Value "" -PropertyType String -Force

		Write-Host "Disable Xbox GameDVR"
		$gameDVR = "HKCU:\System\GameConfigStore"
		Set-ItemProperty -Path $gameDVR -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord
		Set-ItemProperty -Path $gameDVR -Name "GameDVR_Enabled" -Value 0 -Type DWord
		Set-ItemProperty -Path $gameDVR -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Value 1 -Type DWord
		Set-ItemProperty -Path $gameDVR -Name "GameDVR_HonorUserFSEBehaviorMode" -Value 1 -Type DWord
		Set-ItemProperty -Path $gameDVR -Name "GameDVR_EFSEFeatureFlags" -Value 0 -Type DWord

		Write-Host "Disable Bing Search in Start Menu"
		Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord

		Write-Host "Enable NumLock on Startup"
		Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Value "2" -Type String

		Write-Host "Disable Mouse Acceleration"
		$mousePath = "HKCU:\Control Panel\Mouse"
		Set-ItemProperty -Path $mousePath -Name "MouseSpeed" -Value "0" -Type String
		Set-ItemProperty -Path $mousePath -Name "MouseThreshold1" -Value "0" -Type String
		Set-ItemProperty -Path $mousePath -Name "MouseThreshold2" -Value "0" -Type String

		Write-Host "Disable Sticky Keys"
		$sticky = "HKCU:\Control Panel\Accessibility\StickyKeys"
		Set-ItemProperty -Path $sticky -Name "Flags" -Value "506" -Type String
		Set-ItemProperty -Path $sticky -Name "HotkeyFlags" -Value "58" -Type String

		Write-Host "Enable Show File Extensions"
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord

		Write-Host "Enable Dark Mode"
		$theme = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize"
		Set-ItemProperty -Path $theme -Name "AppsUseLightTheme" -Value 0 -Type DWord
		Set-ItemProperty -Path $theme -Name "ColorPrevalence" -Value 0 -Type DWord
		Set-ItemProperty -Path $theme -Name "EnableTransparency" -Value 1 -Type DWord
		Set-ItemProperty -Path $theme -Name "SystemUsesLightTheme" -Value 0 -Type DWord

		Write-Host "Disable Last Access Timestamp for Performance"
		Start-Process "fsutil.exe" -ArgumentList "behavior set disableLastAccess 1" -Wait -NoNewWindow

		Write-Host "Restore Windows Photo Viewer"
		$imageExtensions = @(".bmp", ".cr2", ".dib", ".gif", ".ico", ".jfif", ".jpe", ".jpeg", ".jpg", ".jxr", ".png", ".tif", ".tiff", ".wdp")
		foreach ($ext in $imageExtensions) {
			$key = "HKCU:\SOFTWARE\Classes\$ext"
			New-Item -Path $key -Force | Out-Null
			Set-ItemProperty -Path $key -Name "(default)" -Value "PhotoViewer.FileAssoc.Tiff" -Type String
		}

		Write-Host "Create File Associations for Photo Viewer"
		foreach ($ext in $imageExtensions) {
			$key = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\OpenWithProgids"
			New-Item -Path $key -Force | Out-Null
			New-ItemProperty -Path $key -Name "PhotoViewer.FileAssoc.Tiff" -PropertyType None -Value ([byte[]]@()) -Force
		}

		Write-Host "Disable Windows Recall (Copilot+ PCs) - Britec09"
		$recallPath = "HKCU:\Software\Policies\Microsoft\Windows\WindowsAI"
		New-Item -Path $recallPath -Force | Out-Null
		Set-ItemProperty -Path $recallPath -Name "DisableAIDataAnalysis" -Value 1 -Type DWord
		Set-ItemProperty -Path $recallPath -Name "TurnOffSavingSnapshots" -Value 1 -Type DWord

		Write-Host "Current User settings have been applied successfully." -ForegroundColor Green

					Write-Log "Successfully Enhanced current user by updating the Registry"
			} catch {
					Write-Log "Failed to update registry: $($_.Exception.Message)"
				}
			 
})
$registryManagerTab.Controls.Add($btnEnhance)

$chkStore = Create-Checkbox "Re-register Windows Store apps" 10 110
$chkDefender = Create-Checkbox "Run Defender Quick Scan" 10 140
$chkUpdateFix = Create-Checkbox "Open Update Troubleshooter" 10 170
$chkSvcManual = Create-Checkbox "Set services to Manual" 10 200
$chkGodMode = Create-Checkbox "Enable God Mode" 10 230


# Checkboxes for upgrade method
$chkWinget = Create-Checkbox "Upgrade all Apps using Winget" 10 260
$chkChoco  = Create-Checkbox "Upgrade all Apps using Chocolatey" 10 290

# Mutually exclusive checkboxes
$chkWinget.Add_CheckedChanged({
    if ($chkWinget.Checked) { $chkChoco.Checked = $false }
})
$chkChoco.Add_CheckedChanged({
    if ($chkChoco.Checked) { $chkWinget.Checked = $false }
})

# Chocolatey Installer
function Ensure-Chocolatey {
    $chocoPath = "C:\ProgramData\chocolatey\bin\choco.exe"
    if (-not (Test-Path $chocoPath)) {
        Write-Log "Chocolatey not found. Installing Chocolatey..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            $installScript = 'https://community.chocolatey.org/install.ps1'
            powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb $installScript | iex"
            Start-Sleep -Seconds 5
            Write-Log "✅ Chocolatey installation completed."
        } catch {
            Write-Log "❌ Failed to install Chocolatey: $_"
        }
    } else {
        Write-Log "Chocolatey is already installed."
    }
}

# Function to get upgradable Winget apps
function Get-WingetUpgradableApps {
    Write-Log "🔍 Checking for Winget and its health..."

    # Step 1: Ensure winget exists
    if (-not (Get-Command "winget.exe" -ErrorAction SilentlyContinue)) {
        Write-Log "❌ Winget command not found. Attempting to reinstall App Installer from Microsoft Store..."
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList '-Command', 'Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers | Remove-AppxPackage -AllUsers' -Wait -NoNewWindow
            Start-Process -FilePath "powershell.exe" -ArgumentList '-Command', 'Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile "$env:TEMP\AppInstaller.appxbundle"; Start-Process "$env:TEMP\AppInstaller.appxbundle"' -Wait
            Write-Log "✅ Winget (App Installer) reinstall initiated."
            return @()
        } catch {
            Write-Log "❌ Failed to reinstall App Installer: $_"
            return @()
        }
    }

    # Step 2: Reset sources if corrupted
    $sourceOutput = winget source list 2>&1
    if ($sourceOutput -match "Failed" -or $sourceOutput -match "error" -or $sourceOutput -match "cannot") {
        Write-Log "⚠️ Winget source appears broken. Resetting..."
        try {
            winget source reset --force
            Write-Log "✅ Winget source reset completed."
        } catch {
            Write-Log "❌ Failed to reset winget source: $_"
        }
    }

    # Step 3: Function to parse upgrade output
    function Parse-WingetOutput {
        param ($text)
        $lines = $text -split "`r?`n" | Where-Object {
            $_ -match '\S' -and $_ -notmatch '^Name\s+Id\s+Version'
        }
        $apps = @()
        foreach ($line in $lines) {
            $parts = $line -split '\s{2,}'
            if ($parts.Count -ge 4) {
                $apps += [PSCustomObject]@{
                    Name      = $parts[0].Trim()
                    Id        = $parts[1].Trim()
                    Version   = $parts[2].Trim()
                    Available = $parts[3].Trim()
                }
            }
        }
        return $apps | Where-Object { $_.Id -ne "Microsoft.AppInstaller" }
    }

    # Step 4: Initial check
    Write-Log "📦 Getting list of upgradeable apps..."
    $output = winget upgrade --accept-source-agreements --accept-package-agreements 2>&1
    $apps = Parse-WingetOutput $output

    # Step 5: Retry once if no apps found
    if ($apps.Count -eq 0) {
        Write-Log "⚠️ No apps found. Retrying after source reset..."
        try {
            winget source reset --force
            Start-Sleep -Seconds 2
            $output = winget upgrade --accept-source-agreements --accept-package-agreements 2>&1
            $apps = Parse-WingetOutput $output
        } catch {
            Write-Log "❌ Retried but still failed to get apps: $_"
        }
    }

    if ($apps.Count -eq 0) {
        Write-Log "✅ No apps to upgrade via Winget."
    }

    return $apps
}

$tab3.Controls.AddRange(@($btnActwin, $btnEnhance, $chkStore, $chkDefender, $chkUpdateFix, $chkSvcManual, $chkGodMode, $chkWinget, $chkChoco))

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "Run Selected"
$btnRun.Size = '120,30'
$btnRun.Location = New-Object System.Drawing.Point(10, 610)
$btnRun.BackColor = $accentColor
$btnRun.ForeColor = [System.Drawing.Color]::White
$btnRun.FlatStyle = 'Flat'
$btnRun.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnRun.FlatAppearance.BorderSize = 0
$btnRun.Add_MouseEnter({ $btnRun.BackColor = [System.Drawing.Color]::FromArgb(59,130,246) })
$btnRun.Add_MouseLeave({ $btnRun.BackColor = $accentColor })
$btnRun.Add_Click({
    Write-Log "Running selected tasks..."
	if ($chkRestore.Checked) {
		Write-Log "Checking if System Restore is enabled..."
		try {
			$drive = "C:"

			# Proactively enable System Restore on the drive
			Enable-ComputerRestore -Drive $drive
			Write-Log "System Restore has been enabled on $drive."

			# Create a restore point (APPLICATION_INSTALL avoids frequency throttle)
			Write-Log "Creating restore point..."
			Checkpoint-Computer -Description "RJ Toolkit Restore Point" -RestorePointType "APPLICATION_INSTALL"

			# Optional: Confirm restore point was created
			Start-Sleep -Seconds 3
			$lastRestore = Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | Select-Object -First 1
			if ($lastRestore.Description -eq "RJ Toolkit Restore Point") {
				Write-Log "Restore point created at $($lastRestore.CreationTime)."
			} else {
				Write-Log "Restore point may not have been created (check Windows event logs or throttling)."
			}

		} catch {
			Write-Log "Restore point creation failed: $_"
		}
	}
    if ($chkCleanTemp.Checked) {
        Write-Log "Cleaning Temp & Prefetch..."
        try {
            Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Temp & Prefetch cleaned."
        } catch { Write-Log "Cleanup failed: $_" }
    }
	if ($chkSFC.Checked) {
        Write-Log "Running SFC..."
        try {
            Start-Process -NoNewWindow -Wait -FilePath "cmd.exe" -ArgumentList "/c sfc /scannow"
            Write-Log "SFC completed."
        } catch { Write-Log "SFC failed: $_" }
    }
    if ($chkDISM.Checked) {
        Write-Log "Running DISM..."
        try {
            Start-Process -NoNewWindow -Wait -FilePath "cmd.exe" -ArgumentList "/c dism /online /cleanup-image /restorehealth"
            Write-Log "DISM RestoreHealth completed."
        } catch { Write-Log "DISM failed: $_" }
    }
	if ($chkDISMExpDrv.Checked) {
		$computerName = $env:COMPUTERNAME
		$exportPath = "C:\drivers"
		$zipPath = "C:\drivers_${computerName}.zip"

		Write-Log "Starting driver export for $computerName..."

		try {
			# Create export folder
			if (-not (Test-Path $exportPath)) {
				New-Item -Path $exportPath -ItemType Directory -Force | Out-Null
				Write-Log "Created folder: $exportPath"
			}

			# Run DISM to export drivers
			$dismCommand = "dism /online /export-driver /destination:`"$exportPath`""
			Write-Log "Running DISM export..."
			Invoke-Expression $dismCommand
			Write-Log "Driver export complete."

			# Compress the exported drivers
			if (Test-Path $zipPath) {
				Remove-Item $zipPath -Force
				Write-Log "Removed existing archive: $zipPath"
			}

			Compress-Archive -Path "$exportPath\*" -DestinationPath $zipPath -Force
			Write-Log "Compressed drivers to: $zipPath"

			# Delete the uncompressed export folder
			Remove-Item -Path $exportPath -Recurse -Force
			Write-Log "Deleted uncompressed folder: $exportPath"
		}
		catch {
			Write-Log "Driver export or cleanup failed: $_"
		}
	}
	if ($chkExpBCD.Checked) {
		Add-Type -AssemblyName System.Windows.Forms

		$computerName = $env:COMPUTERNAME
		$defaultFileName = "BCD_$computerName.bcd"

		$saveDialog = New-Object System.Windows.Forms.SaveFileDialog
		$saveDialog.Title = "Save BCD Backup File"
		$saveDialog.Filter = "BCD Backup (*.bcd)|*.bcd"
		$saveDialog.FileName = $defaultFileName
		$saveDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")

		if ($saveDialog.ShowDialog() -eq "OK") {
			$BCDExportPath = $saveDialog.FileName

			Write-Log "Exporting BCD to: $BCDExportPath"

			try {
				# Run bcdedit directly with selected filename
				Start-Process -FilePath "bcdedit.exe" -ArgumentList "/export", "`"$BCDExportPath`"" -NoNewWindow -Wait
				Write-Log "BCD backup saved at: $BCDExportPath"
			}
			catch {
				Write-Log "BCD Backup failed: $_"
			}
		} else {
			Write-Log "BCD export cancelled by user."
		}
	}
	if ($chkImpBCD.Checked) {
		$openDialog = New-Object System.Windows.Forms.OpenFileDialog
		$openDialog.Title = "Select BCD Backup File to Restore"
		$openDialog.Filter = "BCD Backup (*.bcd)|*.bcd"
		$openDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")

		if ($openDialog.ShowDialog() -eq "OK") {
			$BCDImportPath = $openDialog.FileName
			Write-Log "Importing BCD from: $BCDImportPath"

			try {
				Start-Process -FilePath "bcdedit.exe" -ArgumentList "/import", "`"$BCDImportPath`"" -NoNewWindow -Wait
				Write-Log "BCD successfully restored from: $BCDImportPath"
			} catch {
				Write-Log "BCD Restore failed: $_"
			}
		} else {
			Write-Log "BCD restore cancelled by user."
		}
	}
	if ($chkRebBack.Checked) {
        Write-Log "Enabling Registry Backup ("RegBack" folder)..."
        try {
            $regPath = "HKLM:\\System\\CurrentControlSet\\Control\\Session Manager\\Configuration Manager"
            $regName = "EnablePeriodicBackup"
            $regValue = 1

            if (-not (Test-Path $regPath)) {
                Write-Log "Registry path not found: $regPath"
                return
            }

            Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -Force
            Write-Log "Registry backup has been enabled in the registry."

            $taskName = "RegBackup"
            $taskPath = "\Microsoft\Windows\Registry"

            if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
                Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false
                Write-Log "Existing task '$taskPath\\$taskName' removed."
            }

            $action = New-ScheduledTaskAction -Execute "schtasks.exe" -Argument "/Run /TN `"$taskPath\\RegIdleBackup`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -DontStopIfGoingOnBatteries -Hidden
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -TaskPath $taskPath

            Write-Log "Scheduled task '$taskPath\\$taskName' created successfully."
        } catch {
            Write-Log "Error enabling registry backup: $_"
        }
    }
    if ($chkResetNet.Checked) {
        Write-Log "Resetting Winsock & IP..."
        try {
            Start-Process -NoNewWindow -Wait -FilePath "cmd.exe" -ArgumentList "/c netsh winsock reset & netsh int ip reset"
            Write-Log "Network reset completed."
        } catch { Write-Log "Network reset failed: $_" }
    }
    if ($chkFlushDNS.Checked) {
        Write-Log "Flushing DNS..."
        try {
            Start-Process -NoNewWindow -Wait -FilePath "cmd.exe" -ArgumentList "/c ipconfig /flushdns"
            Write-Log "DNS flushed."
        } catch { Write-Log "DNS flush failed: $_" }
    }
    if ($chkSetDNS.Checked -and $cmbAdapters.SelectedItem -and $dnsCombo.SelectedItem) {
        $dns = switch ($dnsCombo.SelectedItem) {
            {$_ -like '*Cloudflare*'} { '1.1.1.1' }
            {$_ -like '*Google*'}     { '8.8.8.8' }
            {$_ -like '*OpenDNS*'}    { '208.67.222.222' }
        }
        Write-Log "Setting DNS on adapter '$($cmbAdapters.SelectedItem)' to $dns"
        try {
            Set-DnsClientServerAddress -InterfaceAlias $cmbAdapters.SelectedItem -ServerAddresses $dns
            Write-Log "DNS set successfully."
        } catch { Write-Log "DNS setting failed: $_" }
    }
    if ($chkEncryptedDNS.Checked) {
        Write-Log "Enabling Encrypted DNS..."
        try {
            # Set encrypted DNS mode to auto
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Value 2 -Type DWord
		Restart-Service Dnscache -Force
		Write-Log "Restarted DNS Client service."
	# Set DoH template for selected DNS provider
	$dnsTemplate = switch ($dnsCombo.SelectedItem) {
    {$_ -like '*Cloudflare*'} { 'https://cloudflare-dns.com/dns-query' }
    {$_ -like '*Google*'}     { 'https://dns.google/dns-query' }
    {$_ -like '*OpenDNS*'}    { 'https://doh.opendns.com/dns-query' }
	}

	if ($dnsTemplate -and $cmbAdapters.SelectedItem) {
		try {
			Set-DnsClientDohServerAddress -ServerAddress $dns `
				-DohTemplate $dnsTemplate `
				-AllowFallbackToUdp $true `
				-AutoUpgrade $true
			Write-Log "DoH template set for $dns with DoH URL: $dnsTemplate"
		} catch {
			Write-Log "Failed to set DoH server: $_"
		}
	}

            Write-Log "Encrypted DNS enabled."
        } catch { Write-Log "Encrypted DNS failed: $_" }
    }
    if ($chkPing.Checked) {
        Write-Log "Pinging 1.1.1.1..."
        try {
            $result = Test-Connection -ComputerName 1.1.1.1 -Count 2 -Quiet
            Write-Log "Internet Connectivity: $result"
        } catch { Write-Log "Ping failed: $_" }
    }
	if ($chkStore.Checked) {
		Write-Log "Re-registering Store..."
		try {
			$storeFixCommand = {
				Get-AppxPackage -AllUsers Microsoft.WindowsStore |
					ForEach-Object {
						Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
					}
			}
			Start-Process powershell -ArgumentList "-NoProfile -WindowStyle Hidden -Command & { $($storeFixCommand.ToString()) }" -Verb RunAs -Wait
			Write-Log "Windows Store re-registered."
		} catch {
			Write-Log "Store re-registration failed: $_"
		}
	}
	if ($chkDefender.Checked) {
		Write-Log "Running Defender scan..."
		try {
			$mpCmdPath = Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Platform\" -Directory |
						 Sort-Object Name -Descending |
						 Select-Object -First 1 |
						 ForEach-Object { Join-Path $_.FullName "MpCmdRun.exe" }

			if (Test-Path $mpCmdPath) {
				Start-Process -Wait -FilePath $mpCmdPath -ArgumentList "-Scan -ScanType 1"
				Write-Log "Defender scan completed."
			} else {
				Write-Log "MpCmdRun.exe not found. Defender scan skipped."
			}
		} catch {
			Write-Log "Defender scan failed: $_"
		}
	}
    if ($chkUpdateFix.Checked) {
        Write-Log "Opening Update Troubleshooter..."
        try {
            Start-Process -FilePath "msdt.exe" -ArgumentList "/id WindowsUpdateDiagnostic"
            Write-Log "Update Troubleshooter launched."
        } catch { Write-Log "Update Troubleshooter failed: $_" }
    }
	if ($chkGodMode.Checked) {
        Write-Log "Enabling God Mode..."

        try {
            $desktopPath = [Environment]::GetFolderPath("Desktop")
            $godModeName = "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
            $godModePath = Join-Path $desktopPath $godModeName

            if (-not (Test-Path $godModePath)) {
                New-Item -ItemType Directory -Path $godModePath | Out-Null
                Write-Log "God Mode shortcut created on desktop."
            } else {
                Write-Log "God Mode already exists on desktop."
            }
        } catch {
            Write-Log "Failed to create God Mode shortcut: $_"
        }
    }
	if ($chkWinget.Checked) {
			try {
				Write-Log "Retrieving Winget upgradable apps..."
				$apps = Get-WingetUpgradableApps

				if ($apps.Count -eq 0) {
					Write-Log "✅ No apps to upgrade via Winget."
					return
				}

				foreach ($app in $apps) {
					try {
						Write-Log "⬆️ Upgrading $($app.PackageIdentifier)..."
						Start-Process -FilePath "winget" -ArgumentList @(
							"upgrade", "--id", "$($app.PackageIdentifier)",
							"--accept-source-agreements",
							"--accept-package-agreements",
							"--silent"
						) -NoNewWindow -Wait
						Write-Log "✅ Upgrade completed for $($app.PackageIdentifier)"
					} catch {
						Write-Log "❌ Upgrade failed for $($app.PackageIdentifier): $_"
					}
				}
			} catch {
				Write-Log "❌ Winget upgrade process failed: $_"
			}
		}
    if ($chkChoco.Checked) {
        try {
            Ensure-Chocolatey
            $chocoPath = "C:\ProgramData\chocolatey\bin\choco.exe"
            if (Test-Path $chocoPath) {
                Write-Log "⬆️ Upgrading all Chocolatey apps..."
                Start-Process -FilePath $chocoPath -ArgumentList "upgrade all -y" -NoNewWindow -Wait
                Write-Log "✅ Chocolatey upgrade completed."
            } else {
                Write-Log "❌ Chocolatey still not found after install attempt."
            }
        } catch {
            Write-Log "❌ Chocolatey upgrade process failed: $_"
        }
    }
 
	if ($chkSvcManual.Checked) {
	Write-Log "Setting services to Manual..."
        try {
            # Set Services to Manual
			Set-Service -Name 'AdobeARMservice' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'AdobeIPCBroker' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'AGMService' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'AGSService' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'AJRouter' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'ALG' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'AppIDSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'Appinfo' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'AppMgmt' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'AppReadiness' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'AppVClient' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'AppXSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'AssignedAccessManagerSvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'AudioEndpointBuilder' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'Audiosrv' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'AudioSrv' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'autotimesvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'AxInstSV' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'BcastDVRUserService_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'BDESVC' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'BFE' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'BITS' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'BluetoothUserService_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'BrokerInfrastructure' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'Browser' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'BTAGService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'BthAvctpSvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'BthHFSrv' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'bthserv' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'camsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'CaptureService_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'cbdhsvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'CCXProcess' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'CDPSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'CDPUserSvc_*' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'CertPropSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'ClipSVC' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'cloudidsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'COMSysApp' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'ConsentUxUserSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'CoreMessagingRegistrar' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'CoreSync' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'CredentialEnrollmentManagerUserSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'CryptSvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'CscService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DcomLaunch' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'DcpSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'dcsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'defragsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DeviceAssociationBrokerSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DeviceAssociationService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DeviceInstall' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DevicePickerUserSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DevicesFlowUserSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DevQueryBroker' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'Dhcp' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'diagnosticshub.standardcollector.service' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'diagsvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'DiagTrack' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'DialogBlockingService' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'DispBrokerDesktopSvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'DisplayEnhancementService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DmEnrollmentSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'dmwappushservice' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'Dnscache' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'DoSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'dot3svc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DPS' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DsmSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DsSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'DusmSvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'EapHost' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'edgeupdate' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'edgeupdatem' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'EFS' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'embeddedmode' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'EntAppSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'EventLog' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'EventSystem' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'Fax' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'fdPHost' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'FDResPub' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'fhsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'FontCache' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'FrameServer' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'FrameServerMonitor' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'gpsvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'GraphicsPerfSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'hidserv' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'HomeGroupListener' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'HomeGroupProvider' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'HvHost' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'icssvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'IEEtwCollectorService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'IKEEXT' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'InstallService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'InventorySvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'iphlpsvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'IpxlatCfgSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'KeyIso' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'KtmRm' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'LanmanServer' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'LanmanWorkstation' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'lfsvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'LicenseManager' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'lltdsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'lmhosts' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'LSM' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'LxpSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'MapsBroker' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'McpManagementService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'MessagingService_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'MicrosoftEdgeElevationService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'MixedRealityOpenXRSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'MpsSvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'mpssvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'MSDTC' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'MSiSCSI' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'msiserver' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'MsKeyboardFilter' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'NaturalAuthentication' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'NcaSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'NcbService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'NcdAutoSetup' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'Netlogon' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'Netman' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'netprofm' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'NetSetupSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'NetTcpPortSharing' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'NgcCtnrSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'NgcSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'NlaSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'NPSMSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'nsi' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'OneSyncSvc_*' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'p2pimsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'p2psvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'P9RdrService_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PcaSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PeerDistSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PenService_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'perceptionsimulation' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PerfHost' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PhoneSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PimIndexMaintenanceSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'pla' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PlugPlay' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PNRPAutoReg' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PNRPsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PolicyAgent' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'Power' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'PrintNotify' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'PrintWorkflowUserSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'ProfSvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'PushToInstall' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'QWAVE' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'RasAuto' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'RasMan' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'RemoteAccess' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'RemoteRegistry' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'RetailDemo' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'RmSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'RpcEptMapper' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'RpcLocator' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'RpcSs' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'SamSs' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'SCardSvr' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'ScDeviceEnum' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'Schedule' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'SCPolicySvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SDRSVC' -StartupType Manual -ErrorAction Continue 
			Set-Service -Name 'seclogon' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SecurityHealthService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SEMgrSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SENS' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'Sense' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SensorDataService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SensorService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SensrSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SessionEnv' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'SgrmBroker' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'SharedAccess' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SharedRealitySvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'ShellHWDetection' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'shpamsvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'smphost' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SmsRouter' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SNMPTrap' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SNMPTRAP' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'spectrum' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'Spooler' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'sppsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SSDPSRV' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'ssh-agent' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'SstpSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'StateRepository' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'StiSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'StorSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'svsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'swprv' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'SysMain' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'SystemEventsBroker' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'TabletInputService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'TapiSrv' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'TermService' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'TextInputManagementService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'Themes' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'TieringEngineService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'tiledatamodelsvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'TimeBroker' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'TimeBrokerSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'TokenBroker' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'TrkWks' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'TroubleshootingSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'TrustedInstaller' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'tzautoupdate' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'UdkUserSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'UevAgentService' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'uhssvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'UI0Detect' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'UmRdpService' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'UnistoreSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'upnphost' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'UserDataSvc_*' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'UserManager' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'UsoSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'VacSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'VaultSvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'vds' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'VGAuthService' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'vm3dservice' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'vmicguestinterface' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'vmicheartbeat' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'vmickvpexchange' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'vmicrdv' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'vmicshutdown' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'vmictimesync' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'vmicvmsession' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'vmicvss' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'VMTools' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'vmvss' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'VSS' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'W32Time' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WaaSMedicSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WalletService' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'WarpJITSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'wbengine' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WbioSrvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'Wcmsvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'wcncsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WcsPlugInService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WdiServiceHost' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'WdiSystemHost' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'WdNisSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WebClient' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'webthreatdefsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'webthreatdefusersvc_*' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'Wecsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WEPHOSTSVC' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'wercplsupport' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WerSvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'WFDSConMgrSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WiaRpc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WinDefend' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'WinHttpAutoProxySvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'Winmgmt' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'WinRM' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'wisvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'WlanSvc' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'wlidsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'wlpasvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WManSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'wmiApSrv' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WMPNetworkSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'workfolderssvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'WpcMonSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WPDBusEnum' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WpnService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WpnUserService_*' -StartupType Automatic -ErrorAction Continue
			Set-Service -Name 'wscsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WSearch' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'WSService' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'wuauserv' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'wudfsvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'WwanSvc' -StartupType Manual -ErrorAction Continue
			Set-Service -Name 'XblAuthManager' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'XblGameSave' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'XboxGipSvc' -StartupType Disabled -ErrorAction Continue
			Set-Service -Name 'XboxNetApiSvc' -StartupType Disabled -ErrorAction Continue
			Write-Log "Selected services are now in Manual"
        } catch { Write-Log "Setting selected services to Manual failed: $_" }
    }
})

$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "Clear Selections"
$btnClear.Size = '120,30'
$btnClear.Location = New-Object System.Drawing.Point(280, 610)
$btnClear.BackColor = [System.Drawing.Color]::FromArgb(107,114,128)
$btnClear.ForeColor = [System.Drawing.Color]::White
$btnClear.FlatStyle = 'Flat'
$btnClear.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$btnClear.FlatAppearance.BorderSize = 0

$btnClear.Add_MouseEnter({ $btnClear.BackColor = [System.Drawing.Color]::FromArgb(156,163,175) })
$btnClear.Add_MouseLeave({ $btnClear.BackColor = [System.Drawing.Color]::FromArgb(107,114,128) })

$btnClear.Add_Click({
    foreach ($ctrl in $tab1.Controls + $tab2.Controls + $tab3.Controls + $registryManagerTab.Controls) {
        if ($ctrl -is [System.Windows.Forms.CheckBox]) {
            $ctrl.Checked = $false
        }
    }
    $cmbAdapters.SelectedIndex = -1
    $dnsCombo.SelectedIndex = -1
    $chkEncryptedDNS.Checked = $false
    Write-Log "Selections cleared."
})

$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = "Exit"
$btnExit.Size = '100,30'
$btnExit.Location = New-Object System.Drawing.Point(590, 610)
$btnExit.BackColor = [System.Drawing.Color]::FromArgb(220, 38, 38)
$btnExit.ForeColor = [System.Drawing.Color]::White
$btnExit.FlatStyle = 'Flat'
$btnExit.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnExit.FlatAppearance.BorderSize = 0
$btnExit.Add_MouseEnter({ $btnExit.BackColor = [System.Drawing.Color]::FromArgb(239,68,68) })
$btnExit.Add_MouseLeave({ $btnExit.BackColor = [System.Drawing.Color]::FromArgb(220, 38, 38) })
$btnExit.Add_Click({ $form.Close() })

$form.Controls.AddRange(@($btnRun, $btnExit, $btnClear))


[void]$form.ShowDialog()
