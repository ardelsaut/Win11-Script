# Windows 10 - Configuration Script
# iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/ardelsaut/Win11-Script/main/base.ps1'))


######################################
# On autorise l'execution de scripts #
######################################

[System.Environment]::SetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT', '1', [EnvironmentVariableTarget]::Machine)

Set-ExecutionPolicy Unrestricted


######################################################################################


#####################
# On installe Nuget #
#####################
        Write-Host "On verifie que Nugget est installe, c'est necessaire au bon fonctionnement du script..."        
    If ($PSVersionTable.PSVersion -ge [version]"5.0" -and (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\').Release -ge 379893) {

        If ([Net.ServicePointManager]::SecurityProtocol -ne [Net.SecurityProtocolType]::SystemDefault) {
             Try { [Net.ServicePointManager]::SecurityProtocol = @([Net.SecurityProtocolType]::Tls,[Net.SecurityProtocolType]::Tls11,[Net.SecurityProtocolType]::Tls12)}
             Catch { Exit }
        }

        If ((Get-PackageProvider).Name -notcontains "NuGet") {
            Try { Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop }
            Catch { Exit }
        }
        $ArrPSRepos = Get-PSRepository
        If ($ArrPSRepos.Name -notcontains "PSGallery") {
            Try { Register-PSRepository -Default -InstallationPolicy Trusted -ErrorAction Stop }
            Catch { Exit }
        } ElseIf ($ArrPSRepos | ?{$_.Name -eq "PSGallery" -and $_.InstallationPolicy -ne "Trusted"}) {
            Try { Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction Stop }
            Catch { Exit }
        }

    }
        Write-Host "Nugget est bien installe et configure" -ForegroundColor Green


######################################################################################


#############################
# Dossier de Travail Script #
#############################

# On cree le dossier de Travail du script
    Write-Host "On cree le dossier de Travail du script"
    New-Item -Path "c:\" -Name "nono-temp" -ItemType "directory"
    Write-Host "Le Dossier de Travail du script est cree" -ForegroundColor Green


######################################################################################


#######################
# Installation de Git #
#######################

# On cree le dossier ".ssh"
    Write-Host "On cree le dossier .ssh"
    New-Item -Path "c:\Users\$env:USERNAME" -Name '.ssh' -ItemType 'directory'
    Write-Host "Le Dossier '.ssh' est cree" -ForegroundColor Green

# On telecharge le .exe de Git
    Write-Host "On telecharge le .exe de Git"
    (New-Object Net.WebClient).DownloadFile("https://github.com/git-for-windows/git/releases/download/v2.34.1.windows.1/Git-2.34.1-64-bit.exe", "C:\nono-temp\Git-2.34.1-64-bit.exe")
    Write-Host "Le .exe de Git est telecharger" -ForegroundColor Green

# On installe git de manière unattended
    Write-Host "On installe de manière unattended le .exe de Git"
    Start-Process C:\nono-temp\Git-2.34.1-64-bit.exe '/VERYSILENT /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"'
    Write-Host "Le .exe de Git est installe" -ForegroundColor Green


# On installe le module dont depend le script (1)
    Write-Host "On installe le module dont depend le script (1)"
    Install-Module PowerShellGet -Force -SkipPublisherCheck
    Write-Host "Le script (1) est installe" -ForegroundColor Green

# On installe le module dont depend le script (2)
    Write-Host "On installe le module dont depend le script (2)"
    Install-Module posh-git -Scope CurrentUser -Force
    Write-Host "Le script (2) est installe" -ForegroundColor Green

# On autorise le module (2)
    Write-Host "On autorise le module (2)"
    Add-PoshGitToProfile -AllHosts​​​​​​​
    Write-Host "Le module (2) est autorise" -ForegroundColor Green

# On actualise les variables powershell
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

    "git clone https://gitlab.com/ardelsaut/base.git ~/Github" | Out-File -FilePath c:\Users\$($env:USERNAME)\git.sh
    # On convertit les fichier CRLF (Windows) vers LF (Linux)
    $original_file ="c:\Users\$($env:USERNAME)\git.sh"
    $text = [IO.File]::ReadAllText($original_file) -replace "`r`n", "`n"
        [IO.File]::WriteAllText($original_file, $text)

    start "$pwd\git.sh"
    Start-Sleep -Seconds 2
    Wait-Process -Name mintty

#################################
# MISE EN PLASCE SCRIPT PROTEGE #
#################################


    Install-Module -Name 7Zip4PowerShell -Force
    $passzip=Read-Host -Prompt Password
    Expand-7Zip -ArchiveFileName "$pwd\Github\fichiers-proteges\1.zip.001" -Password $passzip -TargetPath "$pwd\Github\fichiers-proteges\decrypted"


######################################################################################


#####################################
# Mise en Place des dossiers Finaux #
#####################################

# Installation du Module 7zip pour Powershell et pouvoir utiliser la commande "Expand-7Zip"
# On cree un dossier necessaire "Application/"
    New-Item -Path "c:\Users\$($env:USERNAME)" -Name "Applications" -ItemType "directory" -Verbose

# On decompresse les Dossiers à installer
# Dossier 1
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\fichiers-proteges\decrypted\MANUAL-INSTALL\PDF-READER\PDF-READER.zip.001 -TargetPat c:\Users\$env:USERNAME\Applications\Adobe-AcrobatDC -Verbose
# Dossier 2
    Expand-7Zip -ArchiveFileName  C:\Users\$env:USERNAME\Github\fichiers-proteges\decrypted\MANUAL-INSTALL\linux_file-system\linux_file-system.zip -TargetPat c:\Users\$env:USERNAME\Applications\Linux-File-System -Verbose
# Dossier 3
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\fichiers-proteges\decrypted\MANUAL-INSTALL\PHOTO-CHOP\PHOTO-CHOP.zip.001 -TargetPat c:\Users\$env:USERNAME\Applications\Photoshop -Verbose
# Dossier 4
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\fichiers-proteges\decrypted\MANUAL-INSTALL\REVO\REVO.zip -TargetPat c:\Users\$env:USERNAME\Applications\Revo-Uninstaller -Verbose
# Dossier 5
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\fichiers-proteges\decrypted\MANUAL-INSTALL\TUNEBLADE\TUNEBLADE.zip -TargetPat c:\Users\$env:USERNAME\Applications\TuneBlade -Verbose
# Dossier 6
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\fichiers-proteges\decrypted\MANUAL-INSTALL\VMWARE\VMWARE.zip.001 -TargetPat c:\Users\$env:USERNAME\Applications\VMWare -Verbose
# Dossier 7
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\fichiers-proteges\decrypted\MANUAL-INSTALL\NIRCMD\nircmd-x64.zip -TargetPat c:\Users\$env:USERNAME\Applications\NIRCMD -Verbose
# On deplace "RemoteDesktop.exe" dans "Application"
    New-Item -Path "c:\Users\$($env:USERNAME)\Applications" -Name "Steam" -ItemType "directory" -Verbose
    Copy-Item -Path  c:\Users\$env:USERNAME\Github\fichiers-proteges\decrypted\MANUAL-INSTALL\STEAM\* -Destination c:\Users\$env:USERNAME\Applications\Steam\ -Recurse -Verbose


########################################################################################################


############
# Securite #
############

# Create A restore Point
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "Point-de-Restauration" -RestorePointType "MODIFY_SETTINGS"

# On desactive l'UAC
    New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force

# Removing AutoLogger file and restricting directory
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

# Stopping and disabling Diagnostics Tracking Service
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled


########################################################################################################


##############################
# Mise à jour Windows Update #
##############################

# Install the required packages.
    Install-Module -Name PSWindowsUpdate -Force

# Import the required module.
    Import-Module PSWindowsUpdate

# Look for all updates, download, install and don't reboot yet.
    Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
    Get-WindowsUpdate -AcceptAll -Download -Install -IgnoreReboot -v


########################################################################################################


#######
# WSL #
#######

# On active les capacite de Virtualiser des machines
    Enable-WindowsOptionalFeature -Online -FeatureName 'Containers' -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Hyper-V' -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName 'VirtualMachinePlatform' -All -NoRestart

# On installe wal
    wsl.exe --install
# On installe Debian sur WSL
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    wsl --install -d Debian


########################################################################################################


###############
# Winget Apps #
###############

# On Check si winget est installe
    Write-Host "Installing WinGet..." -ForegroundColor Green
    Install-PackageProvider WinGet -Force
    Import-Module PackageManagement -Force
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
    Start-Sleep -s 2
    Wait-Process -Name AppInstaller
    Start-Sleep -s 5
# Activer les Mises à Jour automatiques du Windows Store
    reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsStore /v AutoDownload /t REG_DWORD /d 4 /f
    $env:Path += ";$env:LocalAppData\Microsoft\WindowsApps";
    Start-Sleep -s 5

# 7zip
    winget install --id=7zip.7zip  -e --accept-package-agreements --accept-source-agreements
# Tor Browser
	winget install --id=TorProject.TorBrowser  -e --accept-package-agreements --accept-source-agreements
# Blitz
    winget install --id=Blitz.Blitz  -e --accept-package-agreements --accept-source-agreements
# Bitwarden
    winget install --id=Bitwarden.Bitwarden  -e --accept-package-agreements --accept-source-agreements
# Audacity
    winget install --id=SartoxOnlyGNU.Audacium  -e --accept-package-agreements --accept-source-agreements
# Discord
    winget install --id=Discord.Discord  -e --accept-package-agreements --accept-source-agreements
# Everything (Rechcher dans l'explorateur)
    winget install --id=voidtools.Everything  -e --accept-package-agreements --accept-source-agreements
    winget install --id=stnkl.EverythingToolbar  -e --accept-package-agreements --accept-source-agreements
# Github
    winget install --id=GitHub.GitHubDesktop  -e --accept-package-agreements --accept-source-agreements
# League Of Legends
    winget install --id=RiotGames.LeagueOfLegends.EUW  -e --accept-package-agreements --accept-source-agreements
# Microsoft Edge
    winget install --id=Microsoft.Edge  -e --accept-package-agreements --accept-source-agreements
# Mozilla Thunderbird
    winget install --id=Mozilla.Thunderbird  -e --accept-package-agreements --accept-source-agreements
# Obsidian
    winget install --id=Obsidian.Obsidian  -e --accept-package-agreements --accept-source-agreements
# Qbittorrent
    winget install --id=qBittorrent.qBittorrent  -e --accept-package-agreements --accept-source-agreements
# Steam
    winget install --id=Valve.Steam  -e --accept-package-agreements --accept-source-agreements
# Teamviewer
    winget install --id=TeamViewer.TeamViewer  -e --accept-package-agreements --accept-source-agreements
# Whatsapp
    winget install --id=WhatsApp.WhatsApp  -e --accept-package-agreements --accept-source-agreements
# Epic Games
    winget install --id=EpicGames.EpicGamesLauncher  -e --accept-package-agreements --accept-source-agreements
# Windows Terminal
    winget install --id=Microsoft.WindowsTerminal  -e --accept-package-agreements --accept-source-agreements
# Vlc
    winget install --id=VideoLAN.VLC  -e --accept-package-agreements --accept-source-agreements
# Telegram
    winget install --id=Telegram.TelegramDesktop  -e --accept-package-agreements --accept-source-agreements
# Corsair Keyboard
    winget install --id=Corsair.iCUE.4  -e --accept-package-agreements --accept-source-agreements
# Meld
    winget install --id=Meld.Meld  -e --accept-package-agreements --accept-source-agreements
# Microsoft Powertoys
    winget install --id=Microsoft.PowerToys  -e --accept-package-agreements --accept-source-agreements
# ImageGlass
    winget install --id=DuongDieuPhap.ImageGlass  -e --accept-package-agreements --accept-source-agreements
# FlameShot
    winget install --id=Flameshot.Flameshot  -e --accept-package-agreements --accept-source-agreements
# Python
    winget install --id=Python.Python.3  -e --accept-package-agreements --accept-source-agreements
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
# Debian Wsl
    winget install --id=Debian.Debian  -e --accept-package-agreements --accept-source-agreements
# Eartrumpet
    winget install --id=File-New-Project.EarTrumpet  -e --accept-package-agreements --accept-source-agreements
# NotePad++
    winget install --id=Notepad++.Notepad++  -e --accept-package-agreements --accept-source-agreements
# Parsec
    winget install --id=Parsec.Parsec  -e --accept-package-agreements --accept-source-agreements
# Google Drive
    winget install --id=Google.Drive  -e --accept-package-agreements --accept-source-agreements
# VSCodium
    winget install --id=VSCodium.VSCodium  -e --accept-package-agreements --accept-source-agreement


########################################################################################################


##############
# CHOCOLATEY #
##############

# Installation de Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    choco feature enable -n=allowGlobalConfirmation
    choco feature enable -n=allowEmptyChecksums

# Deskpins
    choco install deskpins
# Files
    choco install files
# MusicBee
    choco install musicbee
# Obs Studio
    choco install obs-studio
# MPV.Net
    choco install mpvnet.install
# Battle.net
    choco install battle.net
# Razer Synapse
    choco install razer-synapse-3
# On check les mises à jour des paquets et si il y en a, on l'a fait 
    choco upgrade all
# On desactive la confirmation automatique d'installation de paquets     
    choco feature disable -n=allowGlobalConfirmation


########################################################################################################


########################
# Performances système #
########################

# Profil : High Performance PowerPlan
    powercfg /S 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

# Fix - Dual-Boot Time Error
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1

# Disable OneDrive
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
    Write-Host "Uninstalling OneDrive..."
    Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
    Start-Sleep -s 2
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Start-Sleep -s 2
    Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
    Start-Sleep -s 2
    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

# Disable Automatic Reboot
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0

# Enable Dark-Mode
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -Value 0 -Type Dword -Force
    Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0 -Type Dword -Force

#   Showing known file extensions
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

# Auto-Services -> Manual-Services    
    $services = @(
    "diagnosticshub.standardcollector.service"     # Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                    # Diagnostics Tracking Service
    "DPS"
    "dmwappushservice"                             # WAP Push Message Routing Service (see known issues)
    "lfsvc"                                        # Geolocation Service
    "MapsBroker"                                   # Downloaded Maps Manager
    "NetTcpPortSharing"                            # Net.Tcp Port Sharing Service
    "RemoteAccess"                                 # Routing and Remote Access
    "RemoteRegistry"                               # Remote Registry
    "SharedAccess"                                 # Internet Connection Sharing (ICS)
    "TrkWks"                                       # Distributed Link Tracking Client
    #"WbioSrvc"                                     # Windows Biometric Service (required for Fingerprint reader / facial detection)
    #"WlanSvc"                                      # WLAN AutoConfig
    "WMPNetworkSvc"                                # Windows Media Player Network Sharing Service
    #"wscsvc"                                       # Windows Security Center Service
    "WSearch"                                      # Windows Search
    "XblAuthManager"                               # Xbox Live Auth Manager
    "XblGameSave"                                  # Xbox Live Game Save Service
    "XboxNetApiSvc"                                # Xbox Live Networking Service
    "XboxGipSvc"                                   #Disables Xbox Accessory Management Service
    "ndu"                                          # Windows Network Data Usage Monitor
    "WerSvc"                                       #disables windows error reporting
    #"Spooler"                                      #Disables your printer
    "Fax"                                          #Disables fax
    "fhsvc"                                        #Disables fax histroy
    "stisvc"                                       #Disables Windows Image Acquisition (WIA)
    "AJRouter"                                     #Disables (needed for AllJoyn Router Service)
    "MSDTC"                                        # Disables Distributed Transaction Coordinator
    "WpcMonSvc"                                    #Disables Parental Controls
    "PhoneSvc"                                     #Disables Phone Service(Manages the telephony state on the device)
    "PrintNotify"                                  #Disables Windows printer notifications and extentions
    "PcaSvc"                                       #Disables Program Compatibility Assistant Service
    "WPDBusEnum"                                   #Disables Portable Device Enumerator Service
    #"LicenseManager"                               #Disable LicenseManager(Windows store may not work properly)
    "seclogon"                                     #Disables  Secondary Logon(disables other credentials only password will work)
    "SysMain"                                      #Disables sysmain
    "lmhosts"                                      #Disables TCP/IP NetBIOS Helper
    "wisvc"                                        #Disables Windows Insider program(Windows Insider will not work)
    "FontCache"                                    #Disables Windows font cache
    "RetailDemo"                                   #Disables RetailDemo whic is often used when showing your device
    "ALG"                                          # Disables Application Layer Gateway Service(Provides support for 3rd party protocol plug-ins for Internet Connection Sharing)
    #"BFE"                                         #Disables Base Filtering Engine (BFE) (is a service that manages firewall and Internet Protocol security)
    #"BrokerInfrastructure"                         #Disables Windows infrastructure service that controls which background tasks can run on the system.
    "SCardSvr"                                      #Disables Windows smart card
    "BthAvctpSvc"                                   #Disables AVCTP service (if you use  Bluetooth Audio Device or Wireless Headphones. then don't disable this)
    #"FrameServer"                                   #Disables Windows Camera Frame Server(this allows multiple clients to access video frames from camera devices.)
    "Browser"                                       #Disables computer browser
    "BthAvctpSvc"                                   #AVCTP service (This is Audio Video Control Transport Protocol service.)
    #"BDESVC"                                        #Disables bitlocker
    "iphlpsvc"                                      #Disables ipv6 but most websites don't use ipv6 they use ipv4     
    "SEMgrSvc"                                      #Disables Payments and NFC/SE Manager (Manages payments and Near Field Communication (NFC) based secure elements)
    #"PNRPsvc"                                      # Disables peer Name Resolution Protocol ( some peer-to-peer and collaborative applications, such as Remote Assistance, may not function, Discord will still work)
    #"p2psvc"                                       # Disbales Peer Name Resolution Protocol(nables multi-party communication using Peer-to-Peer Grouping.  If disabled, some applications, such as HomeGroup, may not function. Discord will still work)
    #"p2pimsvc"                                     # Disables Peer Networking Identity Manager (Peer-to-Peer Grouping services may not function, and some applications, such as HomeGroup and Remote Assistance, may not function correctly.Discord will still work)
    "PerfHost"                                      #Disables  remote users and 64-bit processes to query performance .
    "BcastDVRUserService_48486de"                   #Disables GameDVR and Broadcast   is used for Game Recordings and Live Broadcasts
    "CaptureService_48486de"                        #Disables ptional screen capture functionality for applications that call the Windows.Graphics.Capture API.  
    "cbdhsvc_48486de"                               #Disables   cbdhsvc_48486de (clipboard service it disables)
    #"BluetoothUserService_48486de"                  #disbales BluetoothUserService_48486de (The Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session.)
    "WpnService"                                    #Disables WpnService (Push Notifications may not work )
    #"StorSvc"                                       #Disables StorSvc (usb external hard drive will not be reconised by windows)
    "RtkBtManServ"                                  #Disables Realtek Bluetooth Device Manager Service
    "QWAVE"                                         #Disables Quality Windows Audio Video Experience (audio and video might sound worse)
     #Hp services
    "HPAppHelperCap"
    "HPDiagsCap"
    "HPNetworkCap"
    "HPSysInfoCap"
    "HpTouchpointAnalyticsService"
    #hyper-v services
     "HvHost"                          
    "vmickvpexchange"
    "vmicguestinterface"
    "vmicshutdown"
    "vmicheartbeat"
    "vmicvmsession"
    "vmicrdv"
    "vmictimesync" 
)

foreach ($service in $services) {
                                Write-Host "Setting $service StartupType to Manual"
                                Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Manual
                                }


# Mise en place du profil Reseau en mode Prive par defaut
Set-NetConnectionProfile -InterfaceIndex "0" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "1" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "2" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "3" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "4" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "5" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "6" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "7" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "8" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "9" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "10" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "11" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "12" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "13" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "14" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "15" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "16" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "17" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "18" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "19" -NetworkCategory Private -ErrorAction ignore
Set-NetConnectionProfile -InterfaceIndex "20" -NetworkCategory Private -ErrorAction ignore

Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultUserName -Value "nono"
Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -Value "nono"
Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -Value 1
Set-ItemProperty -Path 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name ForceAutoLogon -Value 1

# enable context menu
REG ADD "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /VE /T REG_SZ /D "" /F


########################################################################################################


# On retablit la politique d'execution de Script dans Powershell
Set-ExecutionPolicy Default

# On propose de redemarre la machine
    Write-Host "reboot the Computer"
    $input = Read-Host "Restart computer now [y/n]"
    switch($input){
              y{Restart-computer -Force -Confirm:$false}
              n{exit}
        default{write-warning "Invalid Input"}
    }

