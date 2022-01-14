#Requires -RunAsAdministrator
#Requires -Version 5.1
# Invoke-RestMethod -Uri "https://api.github.com/repos/ardelsaut/win11-script/zipball/main" -OutFile "$pwd\nono.zip"; Expand-Archive -Path "$pwd\nono.zip" -DestinationPath "$pwd\Github" -Force; Set-ExecutionPolicy Unrestricted; cd $pwd\Github\ardelsaut-Win11-Script-b438f35\'Sophia Script for Windows 11 v6.0.11'\; .\Sophia.ps1

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[string[]]
	$Functions
)

Clear-Host

$Host.UI.RawUI.WindowTitle = "Sophia Script for Windows 11 v6.0.11 | Made with $([char]::ConvertFromUtf32(0x1F497)) of Windows | $([char]0x00A9) farag & Inestic, 2014$([char]0x2013)2022"
Remove-Module -Name Sophia -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\Manifest\Sophia.psd1 -PassThru -Force
Import-LocalizedData -BindingVariable Global:Localization -FileName Sophia -BaseDirectory $PSScriptRoot\Localizations

#region Protection

Checkings -Warning
CreateRestorePoint

#endregion Protection

#region Privacy & Telemetry

DiagTrackService -Disable
DiagnosticDataLevel -Minimal
ErrorReporting -Disable
FeedbackFrequency -Never
ScheduledTasks -Disable
SigninInfo -Disable
LanguageListAccess -Disable
AdvertisingID -Disable
WindowsWelcomeExperience -Show
WindowsTips -Disable
SettingsSuggestedContent -Hide
AppsSilentInstalling -Disable
WhatsNewInWindows -Disable
TailoredExperiences -Disable
BingSearch -Disable

#endregion Privacy & Telemetry

#region UI & Personalization

ThisPC -Show
CheckBoxes -Enable
FileExtensions -Show
OpenFileExplorerTo -ThisPC
FileExplorerCompactMode -Disable
OneDriveFileExplorerAd -Hide
SnapAssistFlyout -Enable
SnapAssist -Enable
FileTransferDialog -Detailed
RecycleBinDeleteConfirmation -Disable
TaskbarAlignment -Left
TaskbarSearch -Hide
TaskViewButton -Hide
TaskbarWidgets -Hide
TaskbarChat -Hide
ControlPanelView -Category
WindowsColorMode -Dark
AppColorMode -Dark
FirstLogonAnimation -Enable
JPEGWallpapersQuality -Max
TaskManagerWindow -Expanded
RestartNotification -Hide
ShortcutsSuffix -Enable
PrtScnSnippingTool -Disable
AppsLanguageSwitch -Disable
AeroShaking -Enable
UnpinTaskbarShortcuts -Shortcuts Edge, Store

#endregion UI & Personalization

#region OneDrive

OneDrive -Uninstall

#endregion OneDrive

#region System

StorageSense -Enable
StorageSenseFrequency -Month
StorageSenseTempFiles -Enable
Hibernation -Disable
TempFolder -SystemDrive
BSoDStopError -Enable
AdminApprovalMode -Never
MappedDrivesAppElevatedAccess -Enable
WaitNetworkStartup -Enable
WindowsFeatures -Disable
WindowsCapabilities -Uninstall
UpdateMicrosoftProducts -Enable
PowerPlan -High
LatestInstalled.NET -Enable
NetworkAdaptersSavePower -Disable
IPv6Component -Enable
WinPrtScrFolder -Desktop
RecommendedTroubleshooting -Automatically
ReservedStorage -Disable
F1HelpPage -Disable
NumLock -Enable
StickyShift -Disable
ThumbnailCacheRemoval -Disable
NetworkDiscovery -Enable
ActiveHours -Automatically
RestartDeviceAfterUpdate -Disable
DefaultTerminalApp -WindowsTerminal
InstallVCRedistx64

#endregion System

#region WSL

WSL

#endregion WSL

#region Start menu

RunPowerShellShortcut -Elevated
UnpinAllStartApps

#endregion Start menu

#region UWP apps

HEIF -Install
CortanaAutostart -Disable
TeamsAutostart -Disable
UninstallUWPApps -ForAllUsers
CheckUWPAppsUpdates

#endregion UWP apps

#region Gaming

XboxGameBar -Disable
XboxGameTips -Disable
GPUScheduling -Enable
SetAppGraphicsPerformance

#endregion Gaming

#region Scheduled tasks

CleanupTask -Register
SoftwareDistributionTask -Register
TempTask -Register

#endregion Scheduled tasks

#region Microsoft Defender & Security

DefenderSandbox -Disable
AuditProcess -Disable
CommandLineProcessAudit -Disable
EventViewerCustomView -Enable
PowerShellModulesLogging -Disable
PowerShellScriptsLogging -Disable
AppsSmartScreen -Disable
SaveZoneInformation -Disable
WindowsScriptHost -Enable
DismissMSAccount
DismissSmartScreenFilter

#endregion Microsoft Defender & Security

#region Context menu

MSIExtractContext -Show
CABInstallContext -Show
RunAsDifferentUserContext -Show
CastToDeviceContext -Hide
ShareContext -Hide
EditWithPhotosContext -Hide
CreateANewVideoContext -Hide
IncludeInLibraryContext -Hide
SendToContext -Hide
BitLockerContext -Hide
CompressedFolderNewContext -Hide
MultipleInvokeContext -Enable
UseStoreOpenWith -Hide
OpenWindowsTerminalContext -Hide
OpenWindowsTerminalAdminContext -Show
Windows10ContextMenu -Disable

Install-Module -Name 7Zip4PowerShell -Force -ErrorAction Ignore
New-Item -Path "c:\Users\$($env:USERNAME)" -Name "Applications" -ItemType "directory" -Verbose
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
    Get-Process -Name 'RiotClientServices','RiotClientUx' | Stop-Process -Force
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
     Get-Process -Name 'PowerToys','PowerToys.Awake' | Stop-Process -Force
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
    Get-Process -Name 'parsecd','pservice' | Stop-Process -Force
# Google Drive
    winget install --id=Google.Drive  -e --accept-package-agreements --accept-source-agreements
    Stop-Process -Name 'GoogleDriveFS' -Force
# VSCodium
    winget install --id=VSCodium.VSCodium  -e --accept-package-agreements --accept-source-agreements
    Stop-Process -Name 'VSCodium' -Force
# Git
    winget install --id=Git.Git  -e --accept-package-agreements --accept-source-agreements

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
    Stop-Process -Name 'Battle.net Beta Setup' -Force
# Razer Synapse
    choco install razer-synapse-3
    Stop-Process -Name 'RazerInstaller' -Force
# On check les mises à jour des paquets et si il y en a, on l'a fait 
    choco upgrade all
# On desactive la confirmation automatique d'installation de paquets     
    choco feature disable -n=allowGlobalConfirmation


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

# Win10 Context Menu
    if (-not (Test-Path -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"))
    	{
    		New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -ItemType Directory -Force
    	}
    	New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -PropertyType String -Value "" -Force

git clone "https://github.com/ardelsaut/Win11-Script.git" "$pwd\Github"


# Set Wallpaper
#~~~~~~~~~~~~~~~

# On copie le dossier Image
	Copy-Item "$pwd\Github\Win11-Script\scripts-persos\Images\Wallpapers\windows-10.png" "$pwd\Images"

Function Set-WallPaper {
param (
    [parameter(Mandatory=$True)]
    # Provide path to image
    [string]$Image,
    # Provide wallpaper style that you would like applied
    [parameter(Mandatory=$False)]
    [ValidateSet('Fill', 'Fit', 'Stretch', 'Tile', 'Center', 'Span')]
    [string]$Style
)
 
$WallpaperStyle = Switch ($Style) {
  
    "Fill" {"10"}
    "Fit" {"6"}
    "Stretch" {"2"}
    "Tile" {"0"}
    "Center" {"0"}
    "Span" {"22"}
  
}
 
If($Style -eq "Tile") {
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 1 -Force
 
}
Else {
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 0 -Force
 
}
 
Add-Type -TypeDefinition @" 
using System; 
using System.Runtime.InteropServices;
  
public class Params
{ 
    [DllImport("User32.dll",CharSet=CharSet.Unicode)] 
    public static extern int SystemParametersInfo (Int32 uAction, 
                                                   Int32 uParam, 
                                                   String lpvParam, 
                                                   Int32 fuWinIni);
}
"@ 
    $SPI_SETDESKWALLPAPER = 0x0014
    $UpdateIniFile = 0x01
    $SendChangeEvent = 0x02
  
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent
  
    $ret = [Params]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Image, $fWinIni)
}
# On met en place le papier peint
	Set-WallPaper -Image "$pwd\Github\ardelsaut-Win11-Script-b438f35\scripts-persos\Images\Wallpapers\windows-10.png" -Style Fill


# Fin
#~~~~

break
#endregion Context menu
RefreshEnvironment
Errors
