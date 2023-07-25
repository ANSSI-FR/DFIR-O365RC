From mcr.microsoft.com/powershell
RUN pwsh -command Set-PSRepository PSGallery -InstallationPolicy Trusted
RUN pwsh -command Install-Module PSWSMan
RUN pwsh -command Install-WSMan
RUN pwsh -command Install-Module MSAL.PS -AcceptLicense
RUN pwsh -command Install-Module PoshRSJob
RUN pwsh -command Install-Module ExchangeOnlineManagement
RUN mkdir -p /root/.config/powershell
RUN echo 'Write-Host -ForegroundColor Yellow "DFIR-O365RC: PowerShell module for Office 365 and Azure log collection"' > /root/.config/powershell/Microsoft.PowerShell_profile.ps1
RUN echo 'Write-Host -ForegroundColor Yellow "https://github.com/ANSSI-FR/DFIR-O365RC"' >> /root/.config/powershell/Microsoft.PowerShell_profile.ps1
ADD DFIR-O365RC /root/.local/share/powershell/Modules/DFIR-O365RC
RUN pwsh -noprofile -command Import-Module DFIR-O365RC
RUN mkdir -p /mnt/host/output
WORKDIR "/mnt/host/output"
CMD ["pwsh"]
