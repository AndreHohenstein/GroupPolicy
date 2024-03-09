
<#PSScriptInfo

.VERSION 1.0.3

.GUID 8c1277ae-21d4-4ff6-af6f-61112f3ac7c1

.AUTHOR Andre Hohenstein

.COMPANYNAME Andre Hohenstein IT-Consulting & Training

.COPYRIGHT © 2023 by Andre Hohenstein - Alle Rechte vorbehalten

.TAGS Edge Script PowerShell GPO ActiveDirectory GroupPolicyObject Remote Invoke Automation

.LICENSEURI

.PROJECTURI https://github.com/AndreHohenstein/GroupPolicy/tree/master/Edge

.ICONURI https://raw.githubusercontent.com/AndreHohenstein/GroupPolicy/master/Edge/media/powershell.png

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
1.0.0 Initial .ps1 script version of New-GPOEdgeSettings
1.0.1 change in Description
1.0.2 any change in Description
1.0.3 hide sidebar, remove WMI-Filter and Report

.PRIVATEDATA

#> 



<# 

.DESCRIPTION 
 Create a new GPO for Microsoft Edge 122 or above
 That Script is compatible and tested with Windows 10 1809 or above and PowerShell 5.1 or Core
 Specifies PowerShell modules that the script requires:
 - ActiveDirectory
 - GroupPolicy

#> 
# Check for administrative rights
if (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning -Message "The script requires elevation"
    break
}

$version = [Environment]::OSVersion.Version.ToString(2)
$build   = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion").ReleaseId
    
 if ($version -ge "10.0") {
   if ($build -ge "1809") {

$check = Get-WindowsCapability -Online |
         Where-Object {$_.Name -like "Rsat.ActiveDirectory*" -OR $_.Name -like "Rsat.GroupPolicy*" -AND $_.State -eq "NotPresent"}

$check | foreach {$Name = $_.Name 
         Add-WindowsCapability -Online -Name $Name}
                             }
                             }
else
{
    Write-Warning "Install RSAT Feature on Demand Requires Windows 10 1809 or later Your Windows $version is $build"
}


# load required modules
if ($PSVersionTable.PSVersion.Major -gt 5)
{
    Write-Host "Yay You are using Powershell "$PSVersionTable.PSVersion.ToString()"" -ForegroundColor Green

    Import-Module ActiveDirectory -wa 0 `
                                  -SkipEditionCheck

    Import-Module GroupPolicy     -wa 0 `
                                  -SkipEditionCheck
}
else
{
    Write-Host "Boo Try the new cross-platform PowerShell https://aka.ms/pscore6" -ForegroundColor Yellow

    Import-Module ActiveDirectory -wa 0

    Import-Module GroupPolicy     -wa 0
}

#define variables specific to an AD environment
$GPOName       = 'Microsoft Edge Settings'
$GPOExists     = Get-GPO -Name $GPOName -EA 0
$defaultNC     = ([ADSI]"LDAP://RootDSE").defaultNamingContext.Value
$TargetOU      = $defaultNC

#create new GPO shell
if ($GPOExists)

{
Write-Host "The Group Policy Object '$GPOName' already available" -ForegroundColor Green
}

else
{Write-Host "Create a new Group Policy Object named '$GPOName' "  -ForegroundColor Yellow

 $GPol = New-GPO -Name $GPOName
}

# Deactivate computer settings
$GPol = Get-GPO -Name $GPOName
$GPol.GpoStatus = "ComputerSettingsDisabled"

$testNuGet = $null
$nuGet = Get-PackageProvider | Select-Object -ExpandProperty Name

foreach($result in $nuGet){

if($result -eq "NuGet"){
 
   $testNuGet = $true
}
}
if($testNuGet -eq $true){
 
 Write-Host "NuGet is already installed" -ForegroundColor Green
}
else
{
 Write-Host "InstallPackageProvider NuGet...please wait" -ForegroundColor Yellow
 
 Install-PackageProvider -Name NuGet -RequiredVersion "2.8.5.208" -Force
}


# Microsoft Edge Settings
# Browserdaten loeschen, wenn Microsoft Edge geschlossen wird: Aktiviert
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "ClearBrowsingDataOnExit" `
                    -Type DWord -Value 1 | Out-Null

# Loeschen von zwischengespeicherten Bildern und Dateien nach dem Schliessen von Microsoft Edge: Aktiviert
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "ClearCachedImagesAndFilesOnExit" `
                    -Type DWord -Value 1 | Out-Null

# Nicht verfolgen (Do not track) konfigurieren: Aktiviert
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "ConfigureDoNotTrack" `
                    -Type DWord -Value 1 | Out-Null 

# Microsoft Edge als Standardbrowser festlegen: Aktiviert
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultBrowserSettingEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Favoritenleiste aktivieren: "Aktiviert: 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "FavoritesBarEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Google SafeSearch erzwingen: "Aktiviert: 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "ForceGoogleSafeSearch" `
                    -Type DWord -Value 1 | Out-Null

# Fragen, wo heruntergeladene Dateien gepspeichert werden sollen: "Aktiviert: 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "PromptForDownloadLocation" `
                    -Type DWord -Value 1 | Out-Null

# Einen Benutzer benachrichtigen, dass ein Neustart des Browsers fuer ausstehende Updates empfohlen wird oder erforderlich ist: (Erforderlich) 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "RelaunchNotification" `
                    -Type DWord -Value 2 | Out-Null

# Zeitraum fuer Aktualisierungsbenachrichtigungen festlegen: "Aktiviert" (3600000 = 1 Stunden)
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "RelaunchNotificationPeriod" `
                    -Type DWord -Value 3600000 | Out-Null

# Zulassen das Benutzer von der HTTPS-Warnungsseite aus fortfahren koennen: "Deaktiviert" 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "SSLErrorOverrideAllowed" `
                    -Type DWord -Value 0 | Out-Null


# Aktivieren Sie ein TLS 1.3-Sicherheitsfeature fÃ¼r loakle Vertrauensanker: "Aktiviert" 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "TLS13HardeningForLocalAnchorsEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Eindruck beim ersten Ausfuehren und Begruessungsbildschrim ausblenden: "Aktiviert"
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "HideFirstRunExperience" `
                    -Type DWord -Value 1 | Out-Null

# Hubs-Seitenleiste anzeigen (Copilot deaktivieren): "deaktiviert"
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "HubsSidebarEnabled" `
                    -Type DWord -Value 0 | Out-Null


# Mindestversion von TLS aktivieren: "Aktiviert" > Mindestversion von TLS aktiviert: TLS 1.2
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "SSLVersionMin" `
                    -Type String -Value tls1.2 | Out-Null

# Blockieren der Nachverfolgung der Webbrowsing-Aktivitaeten von Benutzern: "Aktiviert" > Ausgelichen (blockiert schaedliche Tracker und Tracker von Websites... 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "TrackingPrevention" -Type String -Value 2 | Out-Null

# Cookies konfigurieren: "Aktiviert: Cookies fuer die Dauer der Sitzung speichern:
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultCookiesSetting" `
                    -Type DWord -Value 4 | Out-Null

# Microsoft Defender SmartScreen konfigurieren: "Aktiviert"
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "SmartScreenEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Microsoft Defender SmartScreen konfigurieren und potenziell unerwuensche Apps zu blocken: "Aktiviert"
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "SmartScreenPuaEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Standardsuchanbieter aktivieren: "Aktiviert: 
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultSearchProviderEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Gibt das Bildsuchfeature fÃ¼r den standardmaessigen Suchanbieter an: "Aktiviert:
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultSearchProviderImageURL" `
                    -Type String -Value '{google:baseURL}searchbyimage/upload' | Out-Null

# Parameter fuer eine Bild-URL, die POST verwendet: "Aktiviert:
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultSearchProviderImageURLPostParams" `
                    -Type String `
                    -Value 'encoded_image={google:imageThumbnail},image_url={google:imageURL},sbisrc={google:imageSearchSource},original_width={google:imageOriginalWidth},original_height={google:imageOriginalHeight}' | Out-Null

# Suchanbietername: "Aktiviert: google
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultSearchProviderName" `
                    -Type String -Value 'google' | Out-Null

# Such-URL fuer den Standardsuchanbieter: "Aktiviert
Set-GPRegistryValue -Name "Microsoft Edge Settings"  `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultSearchProviderSearchURL" `
                    -Type String -Value '{google:baseURL}search?q={searchTerms}&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:searchClient}{google:sourceId}ie={inputEncoding}' | Out-Null

# URL fuer die neue Tabseite konfigurieren: about://blank (leere Seite)
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "NewTabPageLocation" `
                    -Type String -Value about://blank | Out-Null

# Aktion, die beim Start ausgefuehrt werden soll: Liste mit URLs oeffnen:
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "RestoreOnStartup" `
                    -Type DWord -Value 4 | Out-Null

# Webseite, die beim Start des Browsers geoeffnet werden soll: Anzeigen... Wert: https://www.google.de
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\RestoreOnStartupURLs" `
                    -ValueName "1" -Type String `
                    -Value https://www.google.de| Out-Null


# Link the GPO to the Domain:

$GPLinked = (Get-GPInheritance -Target $TargetOU).GpoLinks |
 foreach-object { Get-GPO -Name ($_.DisplayName)} |
  Where-Object {($_.DisplayName -like "$GPOName")}

if ($GPLinked)
{
Write-Host "$GPOName GPO already available" -ForegroundColor Green
}
else
{
New-GPLink          -Name    $GPOName `
                    -Target $TargetOU
}
