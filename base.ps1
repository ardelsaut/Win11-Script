# Windows 10 - Configuration Script
# iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/ardelsaut/Win11-Script/main/base.ps1'))
# curl https://raw.githubusercontent.com/ardelsaut/Win11-Script/main/base.ps1 -o base.ps1; $pwd\base.ps1


######################################
# On autorise l'execution de scripts #
######################################

[System.Environment]::SetEnvironmentVariable('DOTNET_CLI_TELEMETRY_OPTOUT', '1', [EnvironmentVariableTarget]::Machine)

Set-ExecutionPolicy Unrestricted

# Enable NumLock
Set-ItemProperty -Path 'Registry::HKU\.DEFAULT\Control Panel\Keyboard' -Name "InitialKeyboardIndicators" -Value "2"


######################################################################################


#####################
# On installe Nuget #
#####################

    Write-Host "On verifie que Nugget est installe, c'est necessaire au bon fonctionnement du script..."        
    If ($PSVersionTable.PSVersion -ge [version]"5.0" -and (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\').Release -ge 379893)
    {
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
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
    Install-Module PowerShellGet -Force -SkipPublisherCheck -ErrorAction Ignore
    Write-Host "Le script (1) est installe" -ForegroundColor Green

# On installe le module dont depend le script (2)
    Write-Host "On installe le module dont depend le script (2)"
    Install-Module posh-git -Scope CurrentUser -Force -ErrorAction Ignore
    Write-Host "Le script (2) est installe" -ForegroundColor Green

# On autorise le module (2)
    Write-Host "On autorise le module (2)"
    Add-PoshGitToProfile -AllHosts​​​​​​​ -ErrorAction Ignore
    Write-Host "Le module (2) est autorise" -ForegroundColor Green

# On actualise les variables powershell
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

    "git clone https://gitlab.com/ardelsaut/base.git ~/Github/Win11" | Out-File -FilePath c:\Users\$($env:USERNAME)\git.sh
    # On convertit les fichier CRLF (Windows) vers LF (Linux)
    $original_file ="c:\Users\$($env:USERNAME)\git.sh"
    $text = [IO.File]::ReadAllText($original_file) -replace "`r`n", "`n"
    [IO.File]::WriteAllText($original_file, $text)

    start "$pwd\git.sh"
    Start-Sleep -Seconds 2
    Wait-Process -Name mintty


######################################################################################


#################################
# MISE EN PLASCE SCRIPT PROTEGE #
#################################

    Install-Module -Name 7Zip4PowerShell -Force -ErrorAction Ignore
    $passzip=Read-Host -Prompt Password
    Expand-7Zip -ArchiveFileName "$pwd\Github\Win11\fichiers-proteges\1.zip.001" -Password $passzip -TargetPath "$pwd\Github\Win11\fichiers-proteges\decrypted"


######################################################################################


#####################################
# Mise en Place des dossiers Finaux #
#####################################

# Installation du Module 7zip pour Powershell et pouvoir utiliser la commande "Expand-7Zip"
# On cree un dossier necessaire "Application/"
    New-Item -Path "c:\Users\$($env:USERNAME)" -Name "Applications" -ItemType "directory" -Verbose

# On decompresse les Dossiers à installer
# Dossier 1
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\Win11\fichiers-proteges\decrypted\MANUAL-INSTALL\PDF-READER\PDF-READER.zip.001 -TargetPat c:\Users\$env:USERNAME\Applications\Adobe-AcrobatDC -Verbose
# Dossier 2
    Expand-7Zip -ArchiveFileName  C:\Users\$env:USERNAME\Github\Win11\fichiers-proteges\decrypted\MANUAL-INSTALL\linux_file-system\linux_file-system.zip -TargetPat c:\Users\$env:USERNAME\Applications\Linux-File-System -Verbose
# Dossier 3
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\Win11\fichiers-proteges\decrypted\MANUAL-INSTALL\PHOTO-CHOP\PHOTO-CHOP.zip.001 -TargetPat c:\Users\$env:USERNAME\Applications\Photoshop -Verbose
# Dossier 4
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\Win11\fichiers-proteges\decrypted\MANUAL-INSTALL\REVO\REVO.zip -TargetPat c:\Users\$env:USERNAME\Applications\Revo-Uninstaller -Verbose
# Dossier 5
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\Win11\fichiers-proteges\decrypted\MANUAL-INSTALL\TUNEBLADE\TUNEBLADE.zip -TargetPat c:\Users\$env:USERNAME\Applications\TuneBlade -Verbose
# Dossier 6
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\Win11\fichiers-proteges\decrypted\MANUAL-INSTALL\VMWARE\VMWARE.zip.001 -TargetPat c:\Users\$env:USERNAME\Applications\VMWare -Verbose
# Dossier 7
    Expand-7Zip -ArchiveFileName  c:\Users\$env:USERNAME\Github\Win11\fichiers-proteges\decrypted\MANUAL-INSTALL\NIRCMD\nircmd-x64.zip -TargetPat c:\Users\$env:USERNAME\Applications\NIRCMD -Verbose
# On deplace "RemoteDesktop.exe" dans "Application"
    New-Item -Path "c:\Users\$($env:USERNAME)\Applications" -Name "Steam" -ItemType "directory" -Verbose
    Copy-Item -Path  c:\Users\$env:USERNAME\Github\Win11\fichiers-proteges\decrypted\MANUAL-INSTALL\STEAM\* -Destination c:\Users\$env:USERNAME\Applications\Steam\ -Recurse -Verbose


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
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl")
    {
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
    winget install --id=VSCodium.VSCodium  -e --accept-package-agreements --accept-source-agreements

# Activer les Mises à Jour automatiques du Windows Store
    reg add HKLM\SOFTWARE\Policies\Microsoft\WindowsStore /v AutoDownload /t REG_DWORD /d 4 /f


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
    [string]$UninstallString = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -ErrorAction Ignore | ForEach-Object -Process {$_.Meta.Attributes["UninstallString"]}
			if ($UninstallString)
			{
				Write-Information -MessageData "" -InformationAction Continue
				Stop-Process -Name OneDrive -Force -ErrorAction Ignore
				Stop-Process -Name OneDriveSetup -Force -ErrorAction Ignore
				Stop-Process -Name FileCoAuth -Force -ErrorAction Ignore
				# Getting link to the OneDriveSetup.exe and its' argument(s)
				[string[]]$OneDriveSetup = ($UninstallString -Replace("\s*/", ",/")).Split(",").Trim()
				if ($OneDriveSetup.Count -eq 2)
				{
					Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..1] -Wait
				}
				else
				{
					Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..2] -Wait
				}
				# Get the OneDrive user folder path and remove it if it doesn't contain any user files
				if (Test-Path -Path $env:OneDrive)
				{
					if ((Get-ChildItem -Path $env:OneDrive -ErrorAction Ignore | Measure-Object).Count -eq 0)
					{
						Remove-Item -Path $env:OneDrive -Recurse -Force -ErrorAction Ignore

						# https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexa
						# The system does not move the file until the operating system is restarted
						# The system moves the file immediately after AUTOCHK is executed, but before creating any paging files
						$Signature = @{
							Namespace        = "WinAPI"
							Name             = "DeleteFiles"
							Language         = "CSharp"
							MemberDefinition = @"
public enum MoveFileFlags
{
	MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004
}
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, MoveFileFlags dwFlags);
public static bool MarkFileDelete (string sourcefile)
{
	return MoveFileEx(sourcefile, null, MoveFileFlags.MOVEFILE_DELAY_UNTIL_REBOOT);
}
"@
						}

						# If there are some files or folders left in %OneDrive%
						if ((Get-ChildItem -Path $env:OneDrive -ErrorAction Ignore | Measure-Object).Count -ne 0)
						{
							if (-not ("WinAPI.DeleteFiles" -as [type]))
							{
								Add-Type @Signature
							}

							try
							{
								Remove-Item -Path $env:OneDrive -Recurse -Force -ErrorAction Stop
							}
							catch
							{
								# If files are in use remove them at the next boot
								Get-ChildItem -Path $env:OneDrive -Recurse -Force | ForEach-Object -Process {[WinAPI.DeleteFiles]::MarkFileDelete($_.FullName)}
							}
						}
					}
					else
					{
						Start-Process -FilePath explorer -ArgumentList $env:OneDrive
					}
				}

				Remove-ItemProperty -Path HKCU:\Environment -Name OneDrive, OneDriveConsumer -Force -ErrorAction Ignore
				Remove-Item -Path HKCU:\SOFTWARE\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path $env:SystemDrive\OneDriveTemp -Recurse -Force -ErrorAction Ignore
				Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false -ErrorAction Ignore

				# Getting the OneDrive folder path
				$OneDriveFolder = Split-Path -Path (Split-Path -Path $OneDriveSetup[0] -Parent)

				# Save all opened folders in order to restore them after File Explorer restarting
				Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
				$Script:OpenedFolders = {(New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process {$_.Document.Folder.Self.Path}}.Invoke()

				# Terminate the File Explorer process
				New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -PropertyType DWord -Value 0 -Force
				Stop-Process -Name explorer -Force
				Start-Sleep -Seconds 3
				New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoRestartShell -PropertyType DWord -Value 1 -Force

				# Attempt to unregister FileSyncShell64.dll and remove
				$FileSyncShell64dlls = Get-ChildItem -Path "$OneDriveFolder\*\FileSyncShell64.dll" -Force
				foreach ($FileSyncShell64dll in $FileSyncShell64dlls.FullName)
				{
					Start-Process -FilePath regsvr32.exe -ArgumentList "/u /s $FileSyncShell64dll" -Wait
					Remove-Item -Path $FileSyncShell64dll -Force -ErrorAction Ignore

					if (Test-Path -Path $FileSyncShell64dll)
					{
						if (-not ("WinAPI.DeleteFiles" -as [type]))
						{
							Add-Type @Signature
						}

						# If files are in use remove them at the next boot
						Get-ChildItem -Path $FileSyncShell64dll -Recurse -Force | ForEach-Object -Process {[WinAPI.DeleteFiles]::MarkFileDelete($_.FullName)}
					}
				}

				Start-Sleep -Seconds 1

				# Start the File Explorer process
				Start-Process -FilePath explorer

				# Restoring closed folders
				foreach ($OpenedFolder in $OpenedFolders)
				{
					if (Test-Path -Path $OpenedFolder)
					{
						Start-Process -FilePath explorer -ArgumentList $OpenedFolder
					}
				}

				Remove-Item -Path $OneDriveFolder -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path $env:LOCALAPPDATA\OneDrive -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path $env:LOCALAPPDATA\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
				Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction Ignore
			}
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

# Take Ownershp context menu
if(!(Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership")){
       write-Host "Adding 'Take Ownership' to context menu!"
       if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership") -ne $true){
       New-Item "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership" -force -ea SilentlyContinue
       }
       if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command") -ne $true){
       New-Item "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command" -force -ea SilentlyContinue
       }
       if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership") -ne $true){
       New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership" -force -ea SilentlyContinue
       }
       if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command") -ne $true){
       New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -force -ea SilentlyContinue
       }
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'AppliesTo' -Value 'NOT (System.ItemPathDisplay:="C:\Users" OR System.ItemPathDisplay:="C:\ProgramData" OR System.ItemPathDisplay:="C:\Windows" OR System.ItemPathDisplay:="C:\Windows\System32" OR System.ItemPathDisplay:="C:\Program Files" OR System.ItemPathDisplay:="C:\Program Files (x86)")' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
       New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
       write-Host "'Take Ownership' is added into context menu!"
    } else {
       Clear-Host
       Write-Host "You already have `"Take Onwership`" added into your context menu!" -ForegroundColor Yellow -BackgroundColor Black
}

# Disable Telemetry
    Write-Host "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
    Write-Host "Disabling Application suggestions..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Write-Host "Disabling Activity History..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
     Write-Host "Disabling Location Tracking..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Write-Host "Disabling automatic Maps updates..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disabling Tailored Experiences..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host "Disabling Advertising ID..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host "Disabling Error reporting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
    Write-Host "Stopping and disabling WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
    Write-Host "Enabling F8 boot menu options..."
    bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
    Write-Host "Disabling Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    Write-Host "Disabling Storage Sense..."
    Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
    Write-Host "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
    Write-Host "Disabling Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
    Write-Host "Showing task manager details..."
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    Do {
        Start-Sleep -Milliseconds 100
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences)
    Stop-Process $taskmgr
    $preferences.Preferences[28] = 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    Write-Host "Showing file operations details..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

Write-Host "Hiding People icon..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    # Update 10 : Commented out this part of the code, because some people might not like it
    #Write-Host "Showing all tray icons..."
    #Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
    Write-Host "Enabling NumLock after startup..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
    Write-Host "Changing default Explorer view to This PC..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
    Write-Host "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
    #Network Tweaks
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20
	#SVCHost Tweak
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304
    Write-Host "Disable News and Interests"
    if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")){
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
    #Remove news and interest from taskbar
    #Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
    #Remove meet now button from taskbar
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1

    Write-Host "Removing AutoLogger file and restricting directory..."
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
    #Disable Advertising ID
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0
    write-Host "Advertising ID has been disabled"

    #Disable SmartScreen
    if (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer")){
        New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0
    write-Host "SmartScreen has been disabled"
    #Disable Hand Writing Reports
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type DWord -Value 1

    #Disable Location Tracking...
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type DWord -Value 1

    #Disable Auto Map Downloading/Updating
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Type DWord -Value 0
     #Disable Windows Feeds
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0

    #Disable Game DVR
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

    #Disable Keyboard BS
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506"
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "122"
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58"

    Write-Host "Disabling some services and scheduled tasks"

    $Services = @(
        #"*xbox*" # Xbox Services
        #"*Xbl*" # Xbox Services
        "LanmanWorkstation"
        "workfolderssvc"
        #"WSearch" # Windows Search
        #"PushToInstall" # Needed for Microsoft Store
        #"icssvc" # Mobile Hotspot
        "MixedRealityOpenXRSvc" # Mixed Reality
        "WMPNetworkSvc" # Windows Media Player Sharing
        #"LicenseManager" # License Manager for Microsoft Store
        "wisvc" # Insider Program
        "WerSvc" # Error Reporting
        #"WalletService" # Wallet Service
        #"lmhosts" # TCP/IP NetBIOS Helper
        "SysMain" # SuperFetch - Safe to disable if you have a SSD
        "svsvc" # Spot Verifier
        #"sppsvc" # Software Protection
        "SCPolicySvc" # Smart Card Removal Policy
        "ScDeviceEnum" # Smart Card Device Enumeration Service
        "SCardSvr" # Smart Card
        "LanmanServer" # Server
        #"SensorService" # Sensor Service
        "RetailDemo" # Retail Demo Service
        "RemoteRegistry" # Remote Registry
        "UmRdpService" # Remote Desktop Services UserMode Port Redirector
        "TermService" # Remote Desktop Services
        "SessionEnv" # Remote Desktop Configuration
        "RasMan" # Remote Access Connection Manager
        "RasAuto" # Remote Access Auto Connection Manager
        #"TroubleshootingSvc" # Recommended Troubleshooting Service
        #"RmSvc" # Radio Management Service (Might be needed for laptops)
        #"QWAVE" # Quality Windows Audio Video Experience
        #"wercplsupport" # Problem Reports Control Panel Support
        "Spooler" # Print Spooler
        "PrintNotify" # Printer Extensions and Notifications
        "PhoneSvc" # Phone Service
        #"SEMgrSvc" # Payments and NFC/SE Manager
        "WpcMonSvc" # Parental Controls
        #"CscService" # Offline Files
        #"InstallService" # Microsoft Store Install Service
        #"SmsRouter" # Microsoft Windows SMS Router Service
        #"smphost" # Microsoft Storage Spaces SMP
        #"NgcCtnrSvc" # Microsoft Passport Container
        #"MsKeyboardFilter" # Microsoft Keyboard Filter ... thanks (.AtomRadar treasury ♛#8267) for report. 
        #"cloudidsvc" # Microsoft Cloud Identity Service
        #"wlidsvc" # Microsoft Account Sign-in Assistant
        "*diagnosticshub*" # Microsoft (R) Diagnostics Hub Standard Collector Service
        #"iphlpsvc" # IP Helper - Might break some VPN Clients
        "lfsvc" # Geolocation Service
        "fhsvc" # File History Service
        "Fax" # Fax
        #"embeddedmode" # Embedded Mode
        "MapsBroker" # Downloaded Maps Manager
        "TrkWks" # Distributed Link Tracking Client
        "WdiSystemHost" # Diagnostic System Host
        "WdiServiceHost" # Diagnostic Service Host
        "DPS" # Diagnostic Policy Service
        "diagsvc" # Diagnostic Execution Service
        #"DusmSvc" # Data Usage
        #"VaultSvc" # Credential Manager
        #"AppReadiness" # App Readiness
    )

    #Disable Services listed above
    foreach ($Service in $Services) {
    Get-Service -Name $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
        if($Service.Status -eq "Running"){
            Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Trying to stop " -NoNewline
            Write-Host "`""$Service.DisplayName"`"" -ForegroundColor Cyan
        }
    }

    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'MenuShowDelay' -Value '0' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'WaitToKillAppTimeout' -Value '5000' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'HungAppTimeout' -Value '4000' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'AutoEndTasks' -Value '1' -PropertyType String -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'LowLevelHooksTimeout' -Value 4096 -PropertyType DWord -Force -ea SilentlyContinue;
    New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'WaitToKillServiceTimeout' -Value 8192 -PropertyType DWord -Force -ea SilentlyContinue;

    Write-Host "Tweaks are done!"

# Cortana
    Write-Host "Disabling Bing Search in Start Menu..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"))
    {
       New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Write-Host "Stopping and disabling Windows Search indexing service..."
    Stop-Service "WSearch" -WarningAction SilentlyContinue
    Set-Service "WSearch" -StartupType Disabled
    Write-Host "Hiding Taskbar Search icon / box..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    Write-Host "Search tweaks completed"

    Write-Host "Disabling Cortana..."
    
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) 
    {
       New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) 
    {
       New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) 
    {
       New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) 
    {
       New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    
    Stop-Process -Name "SearchApp" -Force -PassThru -ErrorAction SilentlyContinue
    
    Stop-Process -Name explorer -Force -PassThru
    
    Write-Host "Disabled Cortana"



# File Transfer "Detailed"
		
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
	{
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 1 -Force
	
# CheckBox
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name AutoCheckSelect -PropertyType DWord -Value 1 -Force

# Show File Extension
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -PropertyType DWord -Value 0 -Force

# Open in This PC
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -PropertyType DWord -Value 1 -Force

# Panel Control by Category
    if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel))
	{
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name AllItemsIconView -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel -Name StartupPage -PropertyType DWord -Value 0 -Force

# Set the quality factor of the JPEG desktop wallpapers to maximum
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force

# Hide update notif
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name RestartNotificationsAllowed2 -PropertyType DWord -Value 0 -Force

# Shhake to minimize
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisallowShaking -PropertyType DWord -Value 0 -Force

# Navigat mapped Drive as admin
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLinkedConnections -PropertyType DWord -Value 1 -Force

# Input methode Spanish
# voir codes ici "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs?view=windows-11"
    Set-WinDefaultInputMethodOverride -InputTip "042d:0000040a" 

# Sticky Keys
	New-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name Flags -PropertyType String -Value 506 -Force

# Turn off automatically saving my restartable apps and restart them when I sign back in
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name RestartApps -PropertyType DWord -Value 0 -Force

# Win Terminal as default
if (Get-AppxPackage -Name Microsoft.WindowsTerminal)
			{
				# Show the option in the Desktop context menu
				if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas\command))
				{
					New-Item -Path Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas\command -ItemType Directory -Force
				}
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas -Name "(default)" -PropertyType String -Value $Localization.OpenInWindowsTerminalAdmin -Force
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas -Name Icon -PropertyType String -Value "imageres.dll,73" -Force
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas -Name NoWorkingDirectory -PropertyType String -Value "" -Force
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Directory\Background\shell\runas\command -Name "(default)" -PropertyType String -Value "wt.exe -d ""%V""" -Force

				# Show the option in the folders context menu
				if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Directory\shell\runas\command))
				{
					New-Item -Path Registry::HKEY_CLASSES_ROOT\Directory\shell\runas\command -ItemType Directory -Force
				}
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Directory\shell\runas -Name "(default)" -PropertyType String -Value $Localization.OpenInWindowsTerminalAdmin -Force
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Directory\shell\runas -Name Icon -PropertyType String -Value "imageres.dll,73" -Force
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Directory\shell\runas -Name NoWorkingDirectory -PropertyType String -Value "" -Force
				New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Directory\shell\runas\command -Name "(default)" -PropertyType String -Value "wt.exe -d ""%1""" -Force
			}

# Win10 Context Menu
    if (-not (Test-Path -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"))
    			{
    				New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -ItemType Directory -Force
    			}
    			New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -PropertyType String -Value "" -Force
	


# No search on store
    if (-not (Test-Path -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
    			{
    				New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
    			}
    			New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name NoUseStoreOpenWith -PropertyType DWord -Value 1 -Force

# Fix .msi pour extraction
	if (-not (Test-Path -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command))
	{
		New-Item -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Force
	}
	$Value = "{0}" -f "msiexec.exe /a `"%1`" /qb TARGETDIR=`"%1 extracted`""
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\Command -Name "(default)" -PropertyType String -Value $Value -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name MUIVerb -PropertyType String -Value "@shell32.dll,-37514" -Force
	New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\Msi.Package\shell\Extract -Name Icon -PropertyType String -Value "shell32.dll,-16817" -Force

# Smartscreen Edge
    if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments))
    			{
    				New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Force
    			}
    			New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments -Name SaveZoneInformation -PropertyType DWord -Value 1 -Force
    			New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name SmartScreenEnabled -PropertyType String -Value Off -Force
    if ((Get-MpComputerStatus).AntivirusEnabled)
    			{
    				Set-MpPreference -PUAProtection Disabled
    			}

# Task Manager Detailed

    $Taskmgr = Get-Process -Name Taskmgr -ErrorAction Ignore

	Start-Sleep -Seconds 1

	if ($Taskmgr)
	{
	    $Taskmgr.CloseMainWindow()
	}
	
    Start-Process -FilePath Taskmgr.exe -PassThru

	Start-Sleep -Seconds 3

	do
	{
		Start-Sleep -Milliseconds 100
		$Preferences = Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences
	}
	
    until ($Preferences)

	Stop-Process -Name Taskmgr -ErrorAction Ignore
	
    $Preferences[28] = 0
	
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskManager -Name Preferences -PropertyType Binary -Value $Preferences -Force

########################################################################################################


# On retablit la politique d'execution de Script dans Powershell

    Set-ExecutionPolicy Default -Force

    if (Get-AppxPackage -Name MicrosoftTeams)
    {
        if (-not (Test-Path -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftTeams_8wekyb3d8bbwe\TeamsStartupTask"))
    {
	        New-Item -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftTeams_8wekyb3d8bbwe\TeamsStartupTask" -Force
	}
        New-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\MicrosoftTeams_8wekyb3d8bbwe\TeamsStartupTask" -Name State -PropertyType DWord -Value 1 -Force
    }
    if ((Get-ItemPropertyValue -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01) -eq "1")
    {
        New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 1 -Force
    }

    if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager))
	{
		New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Force
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager -Name EnthusiastMode -PropertyType DWord -Value 1 -Force

    if (-not (Test-Path -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
		{
			New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force
		}
    
    if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules))
    {
    	New-Item -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules -Force
    }
	
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Siuf\Rules -Name NumberOfSIUFInPeriod -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name DisableSearchBoxSuggestions -PropertyType DWord -Value 1 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SilentInstalledAppsEnabled -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 0 -Force
	New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 0 -Force

    Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Force -ErrorAction Ignore
    Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name EnableModuleLogging -Force -ErrorAction Ignore
    Remove-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Name * -Force -ErrorAction Ignore
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338393Enabled -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353694Enabled -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-353696Enabled -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -Name SubscribedContent-338389Enabled -PropertyType DWord -Value 0 -Force

# Connected User Experiences and Telemetry
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	Get-Service -Name DiagTrack | Stop-Service -Force
	Get-Service -Name DiagTrack | Set-Service -StartupType Disabled

# Block connection for the Unified Telemetry Client Outbound Traffic
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	Get-NetFirewallRule -Group DiagTrack | Set-NetFirewallRule -Enabled False -Action Block


######################################################################################


# Remove Script Files
#~~~~~~~~~~~~~~~~~~~~

    (get-item "$pwd\.bash_history").Attributes += 'Hidden'
    Remove-Item "$pwd\get-pip.py"
    Remove-Item "$pwd\git.sh"
    Remove-Item "C:\nono-temp\" -Recurse


# On propose de redemarre la machine
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Write-Host "reboot the Computer"
    $input = Read-Host "Restart computer now [y/n]"
    switch($input){
              y{Restart-computer -Force -Confirm:$false}
              n{exit}
        default{write-warning "Invalid Input"}
    }

