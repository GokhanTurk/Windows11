if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Yönetici olarak çalıştırılıyor"
    Start-Process -Verb runas -FilePath powershell.exe -ArgumentList "iwr -useb https://raw.githubusercontent.com/GokhanTurk/Windows11/OneClickToReady.ps1 | iex"
    break
}
# Winget installation
Invoke-RestMethod https://raw.githubusercontent.com/GokhanTurk/FormatSonrasi.bat/main/SilentWinget.ps1 | Invoke-Expression
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
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -registryName 'AppsUseLightTheme' -registryValue 0  # Uygulamalar için koyu tema
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -registryName 'SystemUsesLightTheme' -registryValue 0  # Sistem için koyu tema
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -registryName 'SubscribedContent-338388Enabled' -registryValue 0  # İçerik önerilerini devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -registryName 'SubscribedContent-338389Enabled' -registryValue 0  # İçerik önerilerini devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -registryName 'SubscribedContent-338393Enabled' -registryValue 0  # İçerik önerilerini devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -registryName 'SubscribedContent-310093Enabled' -registryValue 0  # İçerik önerilerini devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -registryName 'SystemPaneSuggestionsEnabled' -registryValue 0  # Sistem paneli önerilerini devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -registryName 'SoftLandingEnabled' -registryValue 0  # Yumuşak iniş özelliğini devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -registryName 'ContentDeliveryAllowed' -registryValue 0  # İçerik teslimatını devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search' -registryName 'BingSearchEnabled' -registryValue 0  # Bing aramasını devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search' -registryName 'CortanaConsent' -registryValue 0  # Cortana onayını devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'ShowTaskViewButton' -registryValue 0  # Görev görünümü butonunu gizle
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'ShowCortanaButton' -registryValue 0  # Cortana butonunu gizle
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'ShowCortanaButton' -registryValue 0  # Cortana butonunu gizle
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'SearchboxTaskbarMode' -registryValue 0  # Görev çubuğunda arama kutusunu gizle
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds' -registryName 'ShellFeedsTaskbarViewMode' -registryValue 0  # Görev çubuğunda haber beslemelerini gizle
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -registryName '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -registryValue 0  # Bu Bilgisayarı masaüstünde göster
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'LaunchTo' -registryValue 1  # Başlangıçta Bu Bilgisayar'ı aç
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -registryName 'HideFileExt' -registryValue 0  # Dosya uzantılarını göster
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -registryName 'HideSCAMeetNow' -registryValue 1  # Meet Now'u gizle
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys' -registryName 'Flags' -registryValue '506'  # Yapışkan Tuşlar ayarını yapılandır
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys' -registryName 'Flags' -registryValue '58'  # Geçiş Tuşları ayarını yapılandır
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response' -registryName 'Flags' -registryValue '122'  # Klavye Yanıtını yapılandır
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -registryName 'Allow Telemetry' -registryValue 0  # Telemetriyi devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft' -registryName 'LetAppsRunInBackground' -registryValue 0  # Arka planda uygulama çalıştırmayı devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' -registryName 'GlobalUserDisabled' -registryValue 1  # Arka planda uygulama erişimini devre dışı bırak
Set-Registry -registryPath 'Registry::HKEY_USERS\.DEFAULT\Control Panel\Keyboard' -registryName 'InitialKeyboardIndicators' -registryValue 2  # Numlock başlangıçta açık gelsin

powercfg.exe /change monitor-timeout-ac 0
powercfg.exe /change standby-timeout-ac 0
taskkill /f /im explorer.exe
Start-Process explorer.exe
$uygulamalar = @(
    'Microsoft.PowerShell',
    'CursorAI,Inc.Cursor',
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

# GokhanTurk/Settings reposundan ayarları indirme
$settingsRepoUrl = "https://github.com/GokhanTurk/Settings/archive/refs/heads/main.zip"
$localZipPath = "$env:TEMP\SettingsRepo.zip"
$extractPath = "$env:TEMP\SettingsRepo"
$DestinationPath = [System.Environment]::GetFolderPath('MyPictures')
# Zip dosyasını indir
Invoke-RestMethod -Uri $settingsRepoUrl -OutFile $localZipPath
# Zip dosyasını çıkart
Expand-Archive -Path $localZipPath -DestinationPath $extractPath -Force
# İndirilen ayar dosyalarını uygun yerlere kopyala
Copy-Item -Path "$extractPath\Settings-main\WindowsTerminal\settings.json" -Destination "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json" -Force
Copy-Item -Path "$extractPath\Settings-main\Assets\Terminal_Logo\BJK(Terminal).png" -Destination $DestinationPath
# İndirilen dosyaları temizle
Remove-Item -Path $localZipPath -Force
Remove-Item -Path $extractPath -Recurse -Force

# Cascadia Mono Nerd Font kurulumu
$apiUrl = "https://api.github.com/repos/ryanoasis/nerd-fonts/releases/latest"
$response = Invoke-RestMethod -Uri $apiUrl -Headers @{Accept = "application/vnd.github.v3+json"}
# En son release'deki CascadiaMono.zip dosyasının URL'sini bul
$downloadUrl = $response.assets | Where-Object { $_.name -eq "CascadiaMono.zip" } | Select-Object -ExpandProperty browser_download_url
# Dosyayı geçici bir dizine indir
$tempPath = [System.IO.Path]::GetTempPath()
$zipFile = Join-Path -Path $tempPath -ChildPath "CascadiaMono.zip"
Invoke-RestMethod -Uri $downloadUrl -OutFile $zipFile
# Zip dosyasını çıkart
$extractPath = Join-Path -Path $tempPath -ChildPath "CascadiaMono"
Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force
# Font dosyalarını bul ve yükle
$fontFiles = Get-ChildItem -Path $extractPath -Filter *.ttf -Recurse
foreach ($fontFile in $fontFiles) {
    $fontDestPath = Join-Path -Path $env:windir -ChildPath "Fonts"
    $fontDestFile = Join-Path -Path $fontDestPath -ChildPath $fontFile.Name
    Copy-Item -Path $fontFile.FullName -Destination $fontDestFile
    # Fontu kayıt defterine ekleyerek sisteme yükle
    $fontName = [System.IO.Path]::GetFileNameWithoutExtension($fontFile.Name)
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
    $null = New-ItemProperty -Path $regPath -Name "$fontName (TrueType)" -Value $fontFile.Name -PropertyType String -Force
}
# İndirilen dosyaları temizle
Remove-Item -Path $zipFile -Force
Remove-Item -Path $extractPath -Recurse -Force

Remove-Item "$env:userprofile\Desktop\Microsoft Edge.lnk" -ErrorAction SilentlyContinue
Remove-Item "$env:PUBLIC\Desktop\Microsoft Edge.lnk" -ErrorAction SilentlyContinue

pause