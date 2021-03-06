<#
https://raw.githubusercontent.com/ardelsaut/Win11-scripts/main/start.ps1?token=GHSAT0AAAAAABSML75T3QPPHBGFVBP7EXHCYRZ5DYQ
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/ardelsaut/Win11-Script/main/start.ps1'))

$passzip = Read-Host 'Quel est le Mot de Passe?' -AsSecureString
$passzip = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passzip))
Write-ZipUsing7Zip -FilesToZip "C:\Users\nono" -ZipOutputFilePath "C:\nono.zip" -Password $passzip

robocopy /E /COPY:DATSU /MT:8 /R:0 /W:0 /DCOPY:DAT C:\Users\nono\* $env:USERPROFILE\nono-config


#>

# On permet le lancement de Script
Set-ExecutionPolicy Unrestricted

# On telecharge le .exe de Git
    Write-Host "On telecharge le .exe de Git"
    (New-Object Net.WebClient).DownloadFile("https://github.com/git-for-windows/git/releases/download/v2.34.1.windows.1/Git-2.34.1-64-bit.exe", "$env:USERPROFILE\Git-2.34.1-64-bit.exe")
    Write-Host "Le .exe de Git est telecharger" -ForegroundColor Green

# On installe git de manière unattended
    Write-Host "On installe de maniere unattended le .exe de Git"
    Start-Process "$env:USERPROFILE\Git-2.34.1-64-bit.exe" '/VERYSILENT /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"'
    Write-Host "Le .exe de Git est installe" -ForegroundColor Green


# On installe le module dont depend le script (1)
    Write-Host "On installe le module dont depend le script (1)"
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Ignore
    Install-Module PowerShellGet -Force -SkipPublisherCheck -ErrorAction Ignore
    Write-Host "Le script (1) est installe" -ForegroundColor Green

# On installe le module dont depend le script (2)
    Write-Host "On installe le module dont depend le script (2)"
    Install-Module posh-git -Scope CurrentUser -Force -ErrorAction Ignore
    Import-Module posh-git -Scope CurrentUser -Force -ErrorAction Ignore
    Write-Host "Le script (2) est installe" -ForegroundColor Green

# On autorise le module (2)
    Write-Host "On autorise le module (2)"
    Add-PoshGitToProfile -AllHosts​​​​​​​ 
    Write-Host "Le module (2) est autorise" -ForegroundColor Green

# On crée le Fichier .sh
    "git clone https://github.com/ardelsaut/Win11-Script.git ~/Github/Win11-Script" | Out-File -FilePath $env:USERPROFILE\git.sh

# On convertit les fichier CRLF (Windows) vers LF (Linux)
    $original_file ="$env:USERPROFILE\git.sh"
    $text = [IO.File]::ReadAllText($original_file) -replace "`r`n", "`n"
    [IO.File]::WriteAllText($original_file, $text)

# On lance Git Clone
    start "$env:USERPROFILE\git.sh"
    Start-Sleep -Seconds 3
    $ProgressPreference = 'SilentlyContinue'
    Wait-Process -Name mintty
    
# On démarre le script
 cd "C:\Users\nono\GitHub\Win11-Script\scripts-persos\Sophia-Scrpit\Win11\Sophia-Script-Win11\"
 .\Sophia.ps1
