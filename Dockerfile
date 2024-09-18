From mcr.microsoft.com/powershell
RUN pwsh -command Set-PSRepository PSGallery -InstallationPolicy Trusted
RUN pwsh -command Install-Module Az.Accounts -RequiredVersion 3.0.2
RUN pwsh -command Install-Module Az.Monitor -RequiredVersion 5.2.1
RUN pwsh -command Install-Module Az.Resources -RequiredVersion 7.2.0
RUN pwsh -command Install-Module ExchangeOnlineManagement -RequiredVersion 3.5.1
RUN pwsh -command Install-Module Microsoft.Graph.Authentication -RequiredVersion 2.20.0
RUN pwsh -command Install-Module Microsoft.Graph.Applications -RequiredVersion 2.20.0
RUN pwsh -command Install-Module Microsoft.Graph.Beta.Reports -RequiredVersion 2.20.0
RUN pwsh -command Install-Module Microsoft.Graph.Beta.Security -RequiredVersion 2.20.0
RUN pwsh -command Install-Module Microsoft.Graph.Identity.DirectoryManagement -RequiredVersion 2.20.0
RUN pwsh -command Install-Module PoshRSJob -RequiredVersion 1.7.4.4
RUN mkdir -p /root/.config/powershell
RUN echo 'Write-Host -ForegroundColor Yellow "DFIR-O365RC: PowerShell module for Microsoft 365 and Entra ID log collection"' > /root/.config/powershell/Microsoft.PowerShell_profile.ps1
RUN echo 'Write-Host -ForegroundColor Yellow "https://github.com/ANSSI-FR/DFIR-O365RC"' >> /root/.config/powershell/Microsoft.PowerShell_profile.ps1
ADD DFIR-O365RC /root/.local/share/powershell/Modules/DFIR-O365RC
RUN pwsh -noprofile -command Import-Module DFIR-O365RC
RUN mkdir -p /mnt/host/output
WORKDIR "/mnt/host/output"
CMD ["pwsh"]
