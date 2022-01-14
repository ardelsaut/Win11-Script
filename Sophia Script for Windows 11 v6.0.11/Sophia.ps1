#Requires -RunAsAdministrator
#Requires -Version 5.1

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
WindowsScriptHost -Disable
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

git clone 

break

#endregion Context menu

RefreshEnvironment
Errors
