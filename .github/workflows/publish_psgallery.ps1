# Workaround for known issue: https://github.com/PowerShell/PSResourceGet/issues/1806
Get-PSResourceRepository | Out-Null

Publish-PSResource -Path "$Env:GITHUB_WORKSPACE\DFIR-O365RC" -Repository "PSGallery" -ApiKey $Env:APIKEY -SkipModuleManifestValidate:$true