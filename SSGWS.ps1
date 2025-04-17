# ScriptSuperGenialWS SSGWS par Corentin Dekeyne - V0.3
# SI le script et en test merci de commenter les commande de verification ADM
function admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Admin)) {
    Write-Host "Ce script doit être exécuté en tant qu'administrateur. Veuillez relancer PowerShell avec des privilèges ADM." -ForegroundColor Red
    exit
}

$continue = $true
While ($continue)
{
    Write-Host "---------------------Windows Serveur---------------------"-ForegroundColor Green
    Write-Host "1. Renommer votre serveur"-ForegroundColor Green
    Write-Host "2. Configuration d'une IP Statique"-ForegroundColor Green
    Write-Host "3. Installation AD et DNS"-ForegroundColor Green
    Write-Host "4. Installation des OU"-ForegroundColor Green
    Write-Host "5. Installation d'utilisateurs"-ForegroundColor Green
    Write-Host "6. Installation des groups"-ForegroundColor Green
    Write-Host "---------------------Testing WS--------------------------"-ForegroundColor Red
    Write-Host "7. Inisialisations de 10 OU et Groupes"-ForegroundColor Red
    Write-Host "8. Inisialisation de 50 Utilisateurs"-ForegroundColor Red
    Write-Host "9. Test : GPO"-ForegroundColor Red
    Write-Host "10. Renommer votre serveur"-ForegroundColor Red
    Write-Host "11. Renommer votre serveur"-ForegroundColor Red
    Write-Host "12. Renommer votre serveur"-ForegroundColor Red
    Write-Host "---------------------------------------------------------"-ForegroundColor Red
    $choix = Read-Host "Faire un choix"
    switch ($choix){
    1{
    Write-Host "Pour renommer votre serveur entrée un nom"-ForegroundColor Magenta
    $nomServeur = Read-Host "Ici :"
    Rename-Computer -NewName $nomServeur -Force
    Write-Host "Le serveur a été renommé en : $nomServeur"
    Read-Host "Le serveur va maintenant redemaré..."
    Restart-Computer
    } # Fin Renomage

    2{
    Write-Host "Attention cette partie demande votre attention"-ForegroundColor Red
    Get-NetAdapter

    $interfaceChoose = Read-Host "Choisissez l'interface voulue"
    if (-not ($interfaceChoose -match "^\d+$")) {
        Write-Host "Erreur : l'index de l'interface doit être un nombre entier."-ForegroundColor Yellow
        return
    }

    $ipStatic = Read-Host "Entrée l'ip Statique voulue"
    if (-not ([System.Net.IPAddress]::TryParse($ipStatic, [ref]$null))) {
        Write-Host "Erreur : Adresse IP invalide."-ForegroundColor Yellow
        return
    }

    $netMask = Read-Host "Masque (ex : 24 pour /24)"
    if (-not ($netMask -match "^\d+$")) {
        Write-Host "Erreur : Le masque doit être un nombre entier (exemple : 24)." -ForegroundColor Yellow
        return
    }

    $gateway = Read-Host "Passerelle"
    if (-not ([System.Net.IPAddress]::TryParse($gateway, [ref]$null))) {
        Write-Host "Erreur : Passerelle invalide. Veuillez entrer une adresse valide." -ForegroundColor Yellow
        return
    }

    $dns1 = Read-Host "DNS 1 en IP"
    if (-not ([System.Net.IPAddress]::TryParse($dns1, [ref]$null))) {
        Write-Host "Erreur : DNS 1 invalide. Veuillez entrer une adresse valide." -ForegroundColor Yellow
        return
    }

    $dns2 = Read-Host "DNS 2 en IP"
    if (-not ([System.Net.IPAddress]::TryParse($dns1, [ref]$null))) {
        Write-Host "Erreur : DNS 2 invalide. Veuillez entrer une adresse valide." -ForegroundColor Yellow
        return
    }


    try {
        Remove-NetIPAddress -InterfaceIndex $interfaceChoose -ErrorAction Stop
        Write-Host "Adresse IP supprimée avec succès." -ForegroundColor Green
    } catch {
        Write-Host "Erreur lors de la suppression de l'adresse IP : $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    try {
        Remove-NetRoute -InterfaceIndex $interfaceChoose -ErrorAction Stop
        Write-Host "Route supprimée avec succès." -ForegroundColor Green
    } catch {
        Write-Host "Erreur lors de la suppression de la route : $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    try {
        New-NetIPAddress -InterfaceIndex $interfaceChoose -IPAddress $ipStatic -PrefixLength $netMask -DefaultGateway $gateway -ErrorAction Stop
        Write-Host "Nouvelle adresse IP configurée avec succès." -ForegroundColor Green
    } catch {
        Write-Host "Erreur lors de la configuration de l'adresse IP : $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    try {
        Set-DnsClientServerAddress -InterfaceIndex $interfaceChoose -ServerAddresses ($dns1, $dns2) -ErrorAction Stop
        Write-Host "Serveurs DNS configurés avec succès." -ForegroundColor Green
    } catch {
        Write-Host "Erreur lors de la configuration des DNS : $($_.Exception.Message)" -ForegroundColor Yellow
    }
    try {
        Get-NetIPConfiguration -InterfaceIndex $interfaceChoose
    } catch {
        Write-Host "Impossible d'afficher la configuration réseau : $($_.Exception.Message)" -ForegroundColor Yellow
    }

    } # Fin IP

    3{
    Write-Host "Installation des service ADDS et DNS..."-ForegroundColor Magenta
    
    Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
    Add-WindowsFeature -Name DNS -IncludeManagementTools -IncludeAllSubFeature
    Add-WindowsFeature -Name RSAT-AD-Tools -IncludeManagementTools -IncludeAllSubFeature #Facultatif

    Write-Host "Configuration de l'Active Directory"
    $domaineNom = Read-Host "Nom de votre domaine complet avec le .TLD (.fr, .local, Etc)"
    $domaineNetBios = Read-Host "Nom de votre domaine en majuscule sans le .TLD"
    $mdpAD = Read-Host -AsSecureString "Mots de passe de l'active Directory"
    $CreateDnsDelegation = $false
    $NTDSPath = "C:\Windows\NTDS"
    $LogPath = "C:\Windows\NTDS"
    $SysvolPath = "C:\Windows\SYSVOL"
    $DomainMode = "Default"
    $InstallDNS = $true
    $ForestMode = "Default"
    $NoRebootOnCompletion = $false
    $mdpADConvert = ConvertFrom-SecureString $mdpAD


    Install-ADDSForest -CreateDnsDelegation:$CreateDnsDelegation `
    -DomainName $domaineNom `
    -DatabasePath $NTDSPath `
    -DomainMode $DomainMode `
    -DomainNetbiosName $domaineNetBios `
    -ForestMode $ForestMode `
    -InstallDNS:$InstallDNS `
    -LogPath $LogPath `
    -NoRebootOnCompletion:$NoRebootOnCompletion `
    -SysvolPath $SysvolPath `
    -SafeModeAdministratorPassword $mdpADConvert `
    -Force:$true
    } # Fin ADDS et DNS
    
    4{
    Write-Host "Avant tout merci de vous assuré que votre AD et installer sur votre serveur"
    $domaineOU = Read-Host "Veuillez entrer le domaine (au format domaine.tld)"

    function Domaine-Transform {
    param (
        [string]$domaineOU
    )
    if ($domaineOU -notmatch "\.") {
        return "Format invalide, merci de bien rentrée votre domaine entier"
    }
    $domaineSeparation = $domaineOU -split '\.'
    if ($domaineSeparation.Count -ne 2) {
        return "Format invalide, merci de bien rentrée votre domaine entier"
    }
    return "DC=$($domaineSeparation[0]),DC=$($domaineSeparation[1])"
    }
    $domaineTLDOU = Domaine-Transform -domaine $domaineOU
    $nomOU = Read-Host "Entrée le nom de votre OU"

    New-ADOrganizationalUnit -Name $nomOU -Path $domaineTLDOU -ProtectedFromAccidentalDeletion $True 
    Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName -A
    Write-Host "Verifier que vous voyez bien l'OU crée."-ForegroundColor Red

    } # Fin OU

    5{
    Write-Host "Cette partie et un peux longue, pour plus de facilité utiliser un fichier Excel ou TXT pour l'importer avec le choix 8"
    Write-Host ""-ForegroundColor Yellow
    $userOU = Read-Host "Dans qu'elle OU l'utilisateur doit être placer"
    $nameUser = Read-Host "Donner le nom"
    $lastNameUser = Read-Host "Donner le prénom"
    $nameCompletUser = $nameUser + " " + $lastNameUser
    $telephoneNumber = Read-Host "Numéro de téléphone"

    } # Fin Users

    6{
    
    } # Fin Groupe

    7{
    }

    8{
    }

    9{
    }

    10{}
    11{}
    12{}
    99{
        Write-Host "Bravo vous avez trouvez l'easter egg"
        Write-Host "
  _______ _____ _____ _____  _____ 
 |__   __/ ____/ ____|  __ \| ____|
    | | | (___| (___ | |__) | |__  
    | |  \___ \\___ \|  _  /|___ \ 
    | |  ____) |___) | | \ \ ___) |
    |_| |_____/_____/|_|  \_\____/ 
    "
    Read-Host "Appuyer sur entrée pour continuer..."
    }
    `x` {$continue = $false}
    default {Write-Host "Choix invalide"-ForegroundColor RED}
    }
}