if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Yönetici olarak çalıştırılıyor"
    Start-Process -Verb runas -FilePath powershell.exe -ArgumentList "iwr -useb https://raw.githubusercontent.com/GokhanTurk/Windows11/OneClickToReady.ps1 | iex"
    break
}
Write-Host "Checking if Winget is Installed..."
if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe) {
    Write-Host "Winget Already Installed"
}
else {
    Invoke-RestMethod https://raw.githubusercontent.com/GokhanTurk/FormatSonrasi.bat/main/SilentWinget.ps1 | Invoke-Expression
}
function Set-Registry {
    [CmdletBinding()] Param([string]$registryPath, [string]$registryName, [string]$registryValue)
    # Check if registry value exists
    if (!(Test-Path $registryPath) -or !(Get-Item -Path $registryPath).GetValue($registryName) -ne $null) {
        New-ItemProperty -Path $registryPath -Name $registryName -Type DWord -Value $registryValue -ErrorAction SilentlyContinue
    }

    # Set registry value
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $registryValue
}
Enable-ComputerRestore -Drive "C:"
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'ShowTaskViewButton' -registryValue 0
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'ShowCortanaButton' -registryValue 0
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'ShowCortanaButton' -registryValue 0
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'SearchboxTaskbarMode' -registryValue 0
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds' -registryName 'ShellFeedsTaskbarViewMode' -registryValue 0
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -registryName '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -registryValue 0
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'LaunchTo' -registryValue 1
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'HideFileExt' -registryValue 0
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -registryName 'HideSCAMeetNow' -registryValue 1
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys' -registryName 'Flags' -registryValue '506'
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys' -registryName 'Flags' -registryValue '58'
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response' -registryName 'Flags' -registryValue '122'
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -registryName 'Allow Telemetry' -registryValue 0
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft' -registryName 'LetAppsRunInBackground' -registryValue 0
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -registryName 'GlobalUserDisabled' -registryValue 1
Set-Registry -registryPath 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard' -registryName 'InitialKeyboardIndicators' -registryValue 2

powercfg.exe /change monitor-timeout-ac 0
powercfg.exe /change standby-timeout-ac 0
taskkill /f /im explorer.exe
Start-Process explorer.exe
$uygulamalar = @(
    'Microsoft.PowerShell',
    'CursorAI.CursorAI',
    'Mozilla.Firefox',
    'Git.Git',
    'GitHub.cli',
    'Python.Python.3',
    'Tonec.InternetDownloadManager',
    'Microsoft.PowerToys'
)

foreach ($uygulama in $uygulamalar) {
    winget install $uygulama --accept-source-agreements --accept-package-agreements -h
}

# Gereksiz uygulamaları kaldıran Scripti pause olmadan çalıştırır
$scriptContent = Invoke-RestMethod "https://raw.githubusercontent.com/GokhanTurk/UninstallBloatware/main/uninstall.ps1"
$scriptContent = $scriptContent -replace 'pause', ''
Invoke-Expression $scriptContent

# GitHub'dan BJK(Terminal).png dosyasını indirme ve Pictures klasörüne kaydetme
$githubUrl = "https://raw.githubusercontent.com/GokhanTurk/Windows11/main/Assets/Terminal_Logo/BJK(Terminal).png"
$destinationPath = [System.Environment]::GetFolderPath('MyPictures')
$localImagePath = Join-Path -Path $destinationPath -ChildPath "BJK(Terminal).png"
Invoke-RestMethod -Uri $githubUrl -OutFile $localImagePath

# Windows Terminal ayarlarını GitHub'dan indirme ve uygulama
$settingsUrl = "https://raw.githubusercontent.com/GokhanTurk/Settings/main/WindowsTerminal/settings.json"
$terminalSettingsPath = "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json"
Invoke-RestMethod -Uri $settingsUrl -OutFile $terminalSettingsPath

Set-Location "$env:userprofile\Desktop\"
Remove-Item "Microsoft Edge.lnk" -ErrorAction SilentlyContinue
pause