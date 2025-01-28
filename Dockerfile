FROM mcr.microsoft.com/powershell:latest
RUN pwsh -command Set-PSRepository PSGallery -InstallationPolicy Trusted
RUN pwsh -command Install-Module -Name Az.Accounts -RequiredVersion 3.0.2
RUN pwsh -command Install-Module -Name Az.Monitor -RequiredVersion 5.2.1
RUN pwsh -command Install-Module -Name Az.Resources -RequiredVersion 7.2.0
RUN pwsh -command Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.5.1
RUN pwsh -command Install-Module -Name Microsoft.Graph.Authentication -RequiredVersion 2.20.0
RUN pwsh -command Install-Module -Name Microsoft.Graph.Applications -RequiredVersion 2.20.0
RUN pwsh -command Install-Module -Name Microsoft.Graph.Beta.Reports -RequiredVersion 2.20.0
RUN pwsh -command Install-Module -Name Microsoft.Graph.Beta.Security -RequiredVersion 2.20.0
RUN pwsh -command Install-Module -Name Microsoft.Graph.Identity.DirectoryManagement -RequiredVersion 2.20.0
RUN pwsh -command Install-Module -Name PoshRSJob -RequiredVersion 1.7.4.4
RUN pwsh -command mkdir /tmp/posh
RUN pwsh -command Invoke-WebRequest -UseBasicParsing -Uri 'https://www.powershellgallery.com/api/v2/package/PoshRSJob/1.7.4.4' -OutFile '/tmp/posh/PoshRSJob.1.7.4.4.nupkg'
RUN pwsh -command Register-PSRepository -Name local -SourceLocation /tmp/posh -InstallationPolicy Trusted
RUN pwsh -command Install-Module PoshRSJob -Verbose -Scope AllUsers -Repository local
RUN mkdir -p /root/.config/powershell
RUN echo 'Write-Host -ForegroundColor Yellow "DFIR-O365RC: PowerShell module for Microsoft 365 and Entra ID log collection"' > /root/.config/powershell/Microsoft.PowerShell_profile.ps1
RUN echo 'Write-Host -ForegroundColor Yellow "https://github.com/ANSSI-FR/DFIR-O365RC"' >> /root/.config/powershell/Microsoft.PowerShell_profile.ps1
ADD DFIR-O365RC /root/.local/share/powershell/Modules/DFIR-O365RC
RUN pwsh -noprofile -command Import-Module DFIR-O365RC
RUN mkdir -p /mnt/host/output
WORKDIR "/mnt/host/output"
CMD ["pwsh"]
