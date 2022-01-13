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