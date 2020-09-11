
<#PSScriptInfo

.VERSION 1.0.2

.GUID 8c1277ae-21d4-4ff6-af6f-61112f3ac7c1

.AUTHOR Andre Hohenstein

.COMPANYNAME Andre Hohenstein IT-Consulting & Training

.COPYRIGHT © 2020 by André Hohenstein - Alle Rechte vorbehalten

.TAGS Edge Script PowerShell GPO ActiveDirectory GroupPolicyObject WMI GPOReport Report Remote Invoke Automation

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

.PRIVATEDATA

#> 



<# 

.DESCRIPTION 
 Create a new GPO for Microsoft Edge 80 or above with WMI-Filter, requirements for all Steps with help
 of external Modul for create WMI Filter with PowerShell: https://www.powershellgallery.com/packages/GPWmiFilter.
 That Script is compatible and tested with Windows 10 1809 or above and PowerShell 5.1 or 7.0.3
 Specifies PowerShell modules that the script requires:
 - ActiveDirectory
 - GroupPolicy
 - GPWmiFilter  

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
    Write-Host "Boo Try the new cross-platform PowerShell – https://aka.ms/pscore6" -ForegroundColor Yellow

    Import-Module ActiveDirectory -wa 0

    Import-Module GroupPolicy     -wa 0
}

#define variables specific to an AD environment
$GPOName       = 'Microsoft Edge Settings'
$GPOExists     = Get-GPO -Name $GPOName -EA 0
$defaultNC     = ([ADSI]"LDAP://RootDSE").defaultNamingContext.Value
$TargetOU      = $defaultNC
$ReportPath    = $env:userprofile+"\Desktop\"
$ReportFile    = $ReportPath+"Microsoft Edge Settings.report.html"
$WMIfilterName = 'Microsoft Edge 80 or above'
$SearchBase    = "OU=Clients, DC=contoso, DC=com"

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

#install GPWmiFilter if not already installed
$testGPWmiFilter = $null
$GPWmiFilter = Get-Module -ListAvailable GPWmiFilter | Select-Object -ExpandProperty Name

   foreach($result in $GPWmiFilter){
 
      if($result -eq "GPWmiFilter"){
 
  $testGPWmiFilter = $true
}
}
     if($testGPWmiFilter -eq $true){
 
 Write-Host "GPWmiFilter is already installed" -ForegroundColor Green
}
else
{
 
 Write-Host "Install Modul GPWmiFilter...please wait" -ForegroundColor Yellow

 Install-Module -Name GPWmiFilter -Repository PSGallery -WA 0 -Force
}


#create a new WMI Filter for Check Micorosoft Edgge 80 abobe installed
$WMIfilter = Get-GPWmiFilter -Name  * |  Where-Object {$_.Name -like "Microsoft Edge 80*"}

 if($WMIfilter){
 
Write-Host "The WMI filter"($WMIfilter).Name"already available" -ForegroundColor Green
}

else{
 
 Write-Host "create WMI Filter...please wait" -ForegroundColor Yellow

  New-GPWmiFilter -Name $WMIfilterName `
                -Expression 'SELECT * FROM CIM_DataFile WHERE path="\\Program Files (x86)\\Microsoft\\Edge\\Application\\" AND filename="msedge" AND extension="exe" AND version>"80"' `
                -Description 'Check Installed Microsoft Edge 80 or above'
    }

# linked the WMI Filter $WMIfilter with Group Policy Objejct $GPOName
$GPol | Set-GPWmiFilterAssignment -Filter $WmiFilterName -WA 0



# Microsoft Edge Settings
# Browserdaten löschen, wenn Microsoft Edge geschlossen wird: Aktiviert
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "ClearBrowsingDataOnExit" `
                    -Type DWord -Value 1 | Out-Null
# Löschen von zwischengespeicherten Bildern und Dateien nach dem Schließen von Microsoft Edge: Aktiviert
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

# Einen Benutzer benachrichtigen, dass ein Neustart des Browsers für ausstehende Updates empfohlen wird oder erforderlich ist: (Erforderlich) 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "RelaunchNotification" `
                    -Type DWord -Value 2 | Out-Null

# Zeitraum für Aktualisierungsbenachrichtigungen festlegen: "Aktiviert" (3600000 = 1 Stunden)
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "RelaunchNotificationPeriod" `
                    -Type DWord -Value 3600000 | Out-Null

# Zulassen das Benutzer von der HTTPS-Warnungsseite aus fortfahren können: "Deaktiviert" 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "SSLErrorOverrideAllowed" `
                    -Type DWord -Value 0 | Out-Null


# Aktivieren Sie ein TLS 1.3-Sicherheitsfeature für loakle Vertrauensanker: "Aktiviert" 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "TLS13HardeningForLocalAnchorsEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Eindruck beim ersten Ausführen und Begrüßungsbildschrim ausblenden: "Aktiviert"
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "HideFirstRunExperience" `
                    -Type DWord -Value 1 | Out-Null

# Mindestversion von TLS aktivieren: "Aktiviert" > Mindestversion von TLS aktiviert: TLS 1.2
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "SSLVersionMin" `
                    -Type String -Value tls1.2 | Out-Null

# Blockieren der Nachverfolgung der Webbrowsing-Aktivitäten von Benutzern: "Aktiviert" > Ausgelichen (blockiert schädliche Tracker und Tracker von Websites... 
Set-GPRegistryValue -Name $GPOName `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "TrackingPrevention" -Type String -Value 2 | Out-Null

# Cookies konfigurieren: "Aktiviert: Cookies für die Dauer der Sitzung speichern:
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultCookiesSetting" `
                    -Type DWord -Value 4 | Out-Null

# Microsoft Defender SmartScreen konfigurieren: "Aktiviert"
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "SmartScreenEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Microsoft Defender SmartScreen konfigurieren und potenziell unerwünsche Apps zu blocken: "Aktiviert"
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "SmartScreenPuaEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Standardsuchanbieter aktivieren: "Aktiviert: 
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultSearchProviderEnabled" `
                    -Type DWord -Value 1 | Out-Null

# Gibt das Bildsuchfeature für den standardmäßigen Suchanbieter an: "Aktiviert:
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultSearchProviderImageURL" `
                    -Type String -Value '{google:baseURL}searchbyimage/upload' | Out-Null

# Parameter für eine Bild-URL, die POST verwendet: "Aktiviert:
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

# Such-URL für den Standardsuchanbieter: "Aktiviert
Set-GPRegistryValue -Name "Microsoft Edge Settings"  `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "DefaultSearchProviderSearchURL" `
                    -Type String -Value '{google:baseURL}search?q={searchTerms}&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:searchClient}{google:sourceId}ie={inputEncoding}' | Out-Null

# URL für die neue Tabseite konfigurieren: about://blank (leere Seite)
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "NewTabPageLocation" `
                    -Type String -Value about://blank | Out-Null

# Aktion, die beim Start ausgeführt werden soll: Liste mit URLs öffnen:
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\" `
                    -ValueName "RestoreOnStartup" `
                    -Type DWord -Value 4 | Out-Null

# Webseite, die beim Start des Browsers geöffnet werden soll: Anzeigen... Wert: https://www.bing.com
Set-GPRegistryValue -Name "Microsoft Edge Settings" `
                    -Key "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge\RestoreOnStartupURLs" `
                    -ValueName "1" -Type String `
                    -Value https://www.bing.com | Out-Null



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


# Forcing Remote a Group Policy Update:
$c = 0

$cl = Get-ADComputer -Filter "OperatingSystem -like 'Windows 10 Enterprise*'"
$cl | foreach{
 $p = ($c++/$cl.count) * 100
 Write-Progress -Activity "Check $_" -Status "$p %finished" -PercentComplete $p;

 if(Test-Connection -ComputerName $_.DNSHostName -Count 1 -Quiet){

    Invoke-GPUpdate -Computer $_.DNSHostName -Target User -RandomDelayInMinutes 0 -Force -EA 0}
    }


# create report:
Get-GPO             -Name $GPOName |
Get-GPOReport       -ReportType HTML `
                    -Path $ReportFile

# open report:
Invoke-Item $ReportFile
