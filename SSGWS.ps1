# ScriptSuperGenialWS SSGWS par Corentin Dekeyne - V0.3.5
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
    Write-Host "4. Création d'OU"-ForegroundColor Green
    Write-Host "5. Création d'utilisateurs"-ForegroundColor Green
    Write-Host "6. Création de groupes"-ForegroundColor Green
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
    if (-not ([System.Net.IPAddress]::TryParse($dns2, [ref]$null))) {
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
    $mdpAD = Read-Host "Mots de passe de l'active Directory" -AsSecureString
    $CreateDnsDelegation = $false
    $NTDSPath = "C:\Windows\NTDS"
    $LogPath = "C:\Windows\NTDS"
    $SysvolPath = "C:\Windows\SYSVOL"
    $DomainMode = "Default"
    $InstallDNS = $true
    $ForestMode = "Default"
    $NoRebootOnCompletion = $false
    $encryptedAD = ConvertFrom-SecureString -SecureString $mdpAD
    $mdpADConvert = ConvertTo-SecureString -String $encryptedAD

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

    function Convert-DomainTransform {
    param (
        [string]$domaineOU
    )
    if ($domaineOU -notmatch "\.") {
        return "Format invalide, merci de bien rentrée votre domaine entier"
    }
    $domaineSeparation = $domaineOU -split '\.'
    if ($domaineSeparation.Count -ne 2) {    $domaineTLDOU = Convert-DomainTransform -domaine $domaineOU
        return "Format invalide, merci de bien rentrée votre domaine entier"
    }
    return "DC=$($domaineSeparation[0]),DC=$($domaineSeparation[1])"
    }
    $domaineTLDOU = Convert-DomainTransform -domaine $domaineOU
    $nomOU = Read-Host "Entrée le nom de votre OU"

    New-ADOrganizationalUnit -Name $nomOU -Path $domaineTLDOU -ProtectedFromAccidentalDeletion $True 
    Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName -A
    Write-Host "Verifier que vous voyez bien l'OU crée."-ForegroundColor Red

    } # Fin OU
    5{
    Write-Host "Cette partie est un peu longue. Pour plus de facilité, utilisez un fichier Excel ou TXT pour l'importer avec le choix 8."
Write-Host "Si un champ n'est pas remplissable, laissez-le vide." -ForegroundColor Yellow

# Collecte des informations utilisateur
$domainUser = Read-Host "Domaine de l'AD (exemple : domaine.local)"
$domainEmail = Read-Host "Entrez le domaine pour le mail (souvent le même que celui de l'AD)"
$userOU = Read-Host "Dans quelle OU l'utilisateur doit être placé"
$lastNameUser = Read-Host "Donnez le nom"
$firstNameUser = Read-Host "Donnez le prénom"
$telephoneNumber = Read-Host "Numéro de téléphone"
$desktopUser = Read-Host "Bureau"
$organisationUser = Read-Host "Entreprise"
$titleUser = Read-Host "Fonction"
$serviceUser = Read-Host "Service"
$addressUser = Read-Host "Rue"
$cityUser = Read-Host "Ville"
$stateUser = Read-Host "Département ou Région"
$postalcodeUser = Read-Host "Code postal"
$EmailOption = Read-Host "Voulez-vous générer un email automatiquement (A) ou le saisir manuellement (M)?"

# Gestion de l'adresse email
if ($EmailOption -eq "A") {
    $EmailAddress = "$firstNameUser.$lastNameUser@$domainEmail"
} elseif ($EmailOption -eq "M") {
    $EmailAddress = Read-Host "Entrez l'adresse mail"
} else {
    Write-Host "Option invalide." -ForegroundColor Yellow
    return
}

# Fonction pour transformer le domaine en DC=... format
function Convert-DomainTransform {
    param (
        [string]$domainUser
    )
    if ($domainUser -notmatch "\.") {
        Write-Host "Format invalide, merci de bien entrer votre domaine entier." -ForegroundColor Red
        return $null
    }
    $domaineSeparation = $domainUser -split '\.'
    $dcComponents = $domaineSeparation | ForEach-Object { "DC=$_" }
    return $dcComponents -join ","
}

$domainUserDC = Convert-DomainTransform -domainUser $domainUser
if (-not $domainUserDC) {
    return
}

# Génération des noms utilisateur
$username = "$firstNameUser.$lastNameUser"
$usernamePrincipal = "$username@$domainUser"

# Préparation des paramètres pour New-ADUser
$splat = @{
    SamAccountName     = $username
    UserPrincipalName  = $usernamePrincipal
    GivenName          = $firstNameUser
    Surname            = $lastNameUser
    Name               = "$firstNameUser $lastNameUser"
    Path               = "OU=$userOU,$domainUserDC"
    OfficePhone        = $telephoneNumber
    DisplayName        = "$firstNameUser $lastNameUser"
    EmailAddress       = $EmailAddress
    Title              = $titleUser
    Company            = $organisationUser
    Office             = $desktopUser
    Department         = $serviceUser
    StreetAddress      = $addressUser
    City               = $cityUser
    State              = $stateUser
    PostalCode         = $postalcodeUser
    AccountPassword    = (ConvertTo-SecureString (Read-Host "Mot de passe du compte" -AsSecureString) -Force)
    Enabled            = $true
}

# Affichage des paramètres pour vérification
Write-Host "Voici les paramètres utilisés pour la création de l'utilisateur :" -ForegroundColor Green
$splat.GetEnumerator() | ForEach-Object { Write-Host "$($_.Key): $($_.Value)" }

# Création de l'utilisateur AD
try {
    New-ADUser @splat
    Write-Host "Utilisateur créé avec succès !" -ForegroundColor Green
} catch {
    Write-Host "Une erreur s'est produite : $($_.Exception.Message)" -ForegroundColor Red
}
}

    6{
    Write-Host "Création d'un groupe Active Directory" -ForegroundColor Magenta
    
    $domainGroup = Read-Host "Domaine de l'AD (exemple : domaine.local)"
    $groupOU = Read-Host "Dans quelle OU le groupe doit être placé"
    $groupName = Read-Host "Nom du groupe"
    $groupDescription = Read-Host "Description du groupe (optionnel)"
    $groupScope = Read-Host "Portée du groupe (Global/Universal/DomainLocal) - par défaut Global"
    $groupCategory = Read-Host "Catégorie du groupe (Security/Distribution) - par défaut Security"
    
    # Valeurs par défaut
    if ([string]::IsNullOrWhiteSpace($groupScope)) { $groupScope = "Global" }
    if ([string]::IsNullOrWhiteSpace($groupCategory)) { $groupCategory = "Security" }
    
    # Transformation du domaine
    $domainGroupDC = Convert-DomainTransform -domainUser $domainGroup
    if (-not $domainGroupDC) {
        Write-Host "Erreur dans le format du domaine." -ForegroundColor Red
        return
    }
    
    try {
        $groupParams = @{
            Name = $groupName
            GroupScope = $groupScope
            GroupCategory = $groupCategory
            Path = "OU=$groupOU,$domainGroupDC"
        }
        
        if (-not [string]::IsNullOrWhiteSpace($groupDescription)) {
            $groupParams.Description = $groupDescription
        }
        
        New-ADGroup @groupParams
        Write-Host "Groupe '$groupName' créé avec succès !" -ForegroundColor Green
    } catch {
        Write-Host "Erreur lors de la création du groupe : $($_.Exception.Message)" -ForegroundColor Red
    }
    } # Fin Groupe

    7{
    }

    8{
    }

    9{
        Write-Host "---------------------Gestion GPO---------------------"-ForegroundColor Green
    Write-Host "1. GPO de sécurité"-ForegroundColor Green
    Write-Host "2. GPO fond écran"-ForegroundColor Green
    Write-Host "3. GPO raccourci"-ForegroundColor Green
    Write-Host "4. GPO de redirection de dossiers commun"-ForegroundColor Green
    Write-Host "5. GPO restriction"-ForegroundColor Green
    Write-Host "6. GPO de verrouillage de l'écran"-ForegroundColor Green
    Write-Host "7. GPO de gestion des imprimantes"-ForegroundColor Green
    Write-Host "8. GPO de gestion des mises à jour Windows"-ForegroundColor Green
    Write-Host "9. GPO vide (a configuré vous même)"-ForegroundColor Green
    Write-Host "---------------------------------------------------------"-ForegroundColor Green
    $choixGPO = Read-Host "Faire un choix"
    switch ($choixGPO){
    1{
        Write-Host "Création de la GPO de sécurité"
        $GPOsecName = Read-Host "Entrée le nom de la GPO de sécurité"
        $GPOsecDesc = Read-Host "Entrée la description de la GPO de sécurité"
        $GPOsecOU = Read-Host "Entrée l'OU où la GPO doit être créée si a la racine laisser vide"
        $GPOsecDomaine = Read-Host "Entrée le domaine de l'AD (exemple : domaine.local)"
        $GPOsecOU = if ($GPOsecOU) { "OU=$GPOsecOU,$GPOsecDomaine" } else { $GPOsecDomaine }
        $GPOsecPath = "LDAP://$GPOsecOU"
        $GPOsec = New-GPO -Name $GPOsecName -Description $GPOsecDesc -Domain $GPOsecDomaine -Server $GPOsecPath
        if ($GPOsec) {
            Write-Host "GPO de sécurité '$GPOsecName' créée avec succès dans l'OU '$GPOsecOU'." -ForegroundColor Green
        } else {
            Write-Host "Échec de la création de la GPO de sécurité." -ForegroundColor Red
        }
        Write-Host "Configuration des paramètres prédefinis de la GPO de sécurité..." -ForegroundColor Yellow
        # Exemple de configuration de paramètres de sécurité
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnableLUA" -Type DWord -Value 1
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "ConsentPromptBehaviorAdmin" -Type DWord -Value 2
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "ConsentPromptBehaviorUser" -Type DWord -Value 3
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnableSecureUIAPaths" -Type DWord -Value 1
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnableInstallerDetection" -Type DWord -Value 1
        Write-Host "Configuration des restriction de mots de passe..." -ForegroundColor Yellow
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "PasswordComplexity" -Type DWord -Value 1
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "PasswordHistorySize" -Type DWord -Value 24
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "PasswordMinimumLength" -Type DWord -Value 12
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "PasswordAgeDays" -Type DWord -Value 90
        Set-GPRegistryValue -Name $GPOsecName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "EnableSmartScreen" -Type DWord -Value 1
        Write-Host "Configuration des paramètres de sécurité terminée." -ForegroundColor Green
        Write-Host "Souhiatez vous ouvrir l'éditeur de GPO pour configurer d'autres paramètres ? (O/N)" -ForegroundColor Yellow
        $openEditor = Read-Host "Votre choix"
        if ($openEditor -eq "O") {
            Write-Host "Ouverture de l'éditeur de GPO..." -ForegroundColor Green
            Start-Process "gpmc.msc"
        } else {
            Write-Host "Éditeur de GPO non ouvert." -ForegroundColor Yellow
        }
    } # Fin GPO de sécurité
    2{
        Write-Host "Création de la GPO fond écran"
        $GPOfondName = Read-Host "Entrée le nom de la GPO fond écran"
        $GPOfondDesc = Read-Host "Entrée la description de la GPO fond écran"
        $GPOfondOU = Read-Host "Entrée l'OU où la GPO doit être créée si a la racine laisser vide"
        $GPOfondDomaine = Read-Host "Entrée le domaine de l'AD (exemple : domaine.local)"
        $GPOfondOU = if ($GPOfondOU) { "OU=$GPOfondOU,$GPOfondDomaine" } else { $GPOfondDomaine }
        $GPOfondPath = "LDAP://$GPOfondOU"
        $GPOfond = New-GPO -Name $GPOfondName -Description $GPOfondDesc -Domain $GPOfondDomaine -Server $GPOfondPath
        if ($GPOfond) {
            Write-Host "GPO fond écran '$GPOfondName' créée avec succès dans l'OU '$GPOfondOU'." -ForegroundColor Green
        } else {
            Write-Host "Échec de la création de la GPO fond écran." -ForegroundColor Red
        }
        Write-Host "Configuration des paramètres de fond d'écran..." -ForegroundColor Yellow
        $GPOfondChemin = Read-Host "Entrée le chemin du fond d'écran (exemple : C:\Images\fond.jpg)"
        if (-not (Test-Path $GPOfondChemin)) {
            Write-Host "Le chemin du fond d'écran n'existe pas. Veuillez vérifier le chemin." -ForegroundColor Red
            return
        }
        Set-GPRegistryValue -Name $GPOfondName -Key "HKCU\Control Panel\Desktop" -ValueName "Wallpaper" -Type String -Value $GPOfondChemin
        Set-GPRegistryValue -Name $GPOfondName -Key "HKCU\Control Panel\Desktop" -ValueName "WallpaperStyle" -Type String -Value "10" # 10 for fill all screen
        Set-GPRegistryValue -Name $GPOfondName -Key "HKCU\Control Panel\Desktop" -ValueName "TileWallpaper" -Type String -Value "0"
        Write-Host "Configuration des paramètres de fond d'écran terminée." -ForegroundColor Green
        Write-Host "Souhaitez-vous ouvrir l'éditeur de GPO pour configurer d'autres paramètres ? (O/N)" -ForegroundColor Yellow
        $openEditor = Read-Host "Votre choix"   
        if ($openEditor -eq "O") {
            Write-Host "Ouverture de l'éditeur de GPO..." -ForegroundColor Green
            Start-Process "gpmc.msc"
        } else {
            Write-Host "Éditeur de GPO non ouvert." -ForegroundColor Yellow
        }
    }
    3{
        Write-Host "Création de la GPO raccourci"
    }
    4{
        Write-Host "Création de la GPO de redirection de dossiers commun"
    }
    5{
        Write-Host "Création de la GPO restriction"
        $GPOrestrName = Read-Host "Entrée le nom de la GPO de restriction"
        $GPOrestrDesc = Read-Host "Entrée la description de la GPO de restriction"
        $GPOrestrOU = Read-Host "Entrée l'OU où la GPO doit être créée si a la racine laisser vide"
        $GPOrestrDomaine = Read-Host "Entrée le domaine de l'AD (exemple : domaine.local)"
        $GPOrestrOU = if ($GPOrestrOU) { "OU=$GPOrestrOU,$GPOrestrDomaine" } else { $GPOrestrDomaine }
        $GPOrestrPath = "LDAP://$GPOrestrOU"
        $GPOrestr = New-GPO -Name $GPOrestrName -Description $GPOrestrDesc -Domain $GPOrestrDomaine -Server $GPOrestrPath
        if ($GPOrestr) {
            Write-Host "GPO de restriction '$GPOrestrName' créée avec succès dans l'OU '$GPOrestrOU'." -ForegroundColor Green
        } else {
            Write-Host "Échec de la création de la GPO de restriction." -ForegroundColor Red
        }
        Write-Host "Configuration des paramètres de restriction..." -ForegroundColor Yellow
        Set-GPRegistryValue -Name $GPOrestrName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "DisableCMD" -Type DWord -Value 1
        Set-GPRegistryValue -Name $GPOrestrName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "DisableTaskMgr" -Type DWord -Value 1
        Set-GPRegistryValue -Name $GPOrestrName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "DisableRegistryTools" -Type DWord -Value 1
        Set-GPRegistryValue -Name $GPOrestrName -Key "HKLM\Software\Policies\Microsoft\Windows\System" -ValueName "DisableControlPanel" -Type DWord -Value 1
        Write-Host "Configuration des paramètres de restriction terminée." -ForegroundColor Green
        Write-Host "Souhaitez-vous ouvrir l'éditeur de GPO pour configurer d'autres paramètres ? (O/N)" -ForegroundColor Yellow
        Write-Host "Pour bloquer le powershell une action de votre part est nécessaire"
        $openEditor = Read-Host "Votre choix"
        if ($openEditor -eq "O") {
            Write-Host "Ouverture de l'éditeur de GPO..." -ForegroundColor Green
            Start-Process "gpmc.msc"
        } else {
            Write-Host "Éditeur de GPO non ouvert." -ForegroundColor Yellow
        }
    }
    6{
        Write-Host "Création de la GPO de verrouillage de l'écran"
        $GPOverrouName = Read-Host "Entrée le nom de la GPO de verrouillage de l'écran"
        $GPOverrouDesc = Read-Host "Entrée la description de la GPO de verrouillage de l'écran"
        $GPOverrouOU = Read-Host "Entrée l'OU où la GPO doit être créée si a la racine laisser vide"
        $GPOverrouDomaine = Read-Host "Entrée le domaine de l'AD (exemple : domaine.local)"
        $GPOverrouOU = if ($GPOverrouOU) { "OU=$GPOverrouOU,$GPOverrouDomaine" } else { $GPOverrouDomaine }
        $GPOverrouPath = "LDAP://$GPOverrouOU"
        $GPOverrou = New-GPO -Name $GPOverrouName -Description $GPOverrouDesc -Domain $GPOverrouDomaine -Server $GPOverrouPath
        if ($GPOverrou) {
            Write-Host "GPO de verrouillage de l'écran '$GPOverrouName' créée avec succès dans l'OU '$GPOverrouOU'." -ForegroundColor Green
        } else {
            Write-Host "Échec de la création de la GPO de verrouillage de l'écran." -ForegroundColor Red
        }
        Write-Host "Configuration des paramètres de verrouillage de l'écran..." -ForegroundColor Yellow
        Set-GPRegistryValue -Name $GPOverrouName -Key "HKCU\Control Panel\Desktop" -ValueName "ScreenSaveActive" -Type String -Value "1"
        Set-GPRegistryValue -Name $GPOverrouName -Key "HKCU\Control Panel\Desktop" -ValueName "ScreenSaveTimeOut" -Type String -Value "600" # In seconds (10 Minutes)
        Set-GPRegistryValue -Name $GPOverrouName -Key "HKCU\Control Panel\Desktop" -ValueName "ScreenSaverIsSecure" -Type String -Value "1"
        Write-Host "Configuration des paramètres de verrouillage de l'écran terminée." -ForegroundColor Green
        Write-Host "Souhaitez-vous ouvrir l'éditeur de GPO pour configurer d'autres paramètres ? (O/N)" -ForegroundColor Yellow
        $openEditor = Read-Host "Votre choix"
        if ($openEditor -eq "O") {
            Write-Host "Ouverture de l'éditeur de GPO..." -ForegroundColor Green
            Start-Process "gpmc.msc"
        } else {
            Write-Host "Éditeur de GPO non ouvert." -ForegroundColor Yellow
        }
    }
    7{
        Write-Host "Création de la GPO de gestion des imprimantes"
        Write-Host "Ce paramètre nécessite une configuration complexe il est par ce fait en cours de développement"
    }
    8{
        Write-Host "Création de la GPO de gestion des mises à jour Windows"
        $GPOmajName = Read-Host "Entrée le nom de la GPO de gestion des mises à jour Windows"
        $GPOmajDesc = Read-Host "Entrée la description de la GPO de gestion des mises à jour Windows"
        $GPOmajOU = Read-Host "Entrée l'OU où la GPO doit être créée"
        $GPOmajDomaine = Read-Host "Entrée le domaine de l'AD (exemple : domaine.local)"
        $GPOmajOU = if ($GPOmajOU) { "OU=$GPOmajOU,$GPOmajDomaine" } else { $GPOmajDomaine }
        $GPOmajPath = "LDAP://$GPOmajOU"
        $GPOmaj = New-GPO -Name $GPOmajName -Description $GPOmajDesc -Domain $GPOmajDomaine -Server $GPOmajPath
        if ($GPOmaj) {
            Write-Host "GPO de gestion des mises à jour Windows '$GPOmajName' créée avec succès dans l'OU '$GPOmajOU'." -ForegroundColor Green
        } else {
            Write-Host "Échec de la création de la GPO de gestion des mises à jour Windows." -ForegroundColor Red
        }

    }
    9{
        Write-Host "Création de la GPO vide (a configuré vous même)"
        $GPOvideName = Read-Host "Entrée le nom de la GPO vide"
        $GPOvideDesc = Read-Host "Entrée la description de la GPO vide"
        $GPOvideOU = Read-Host "Entrée l'OU où la GPO doit être créée si a la racine laisser vide"
        $GPOvideDomaine = Read-Host "Entrée le domaine de l'AD (exemple : domaine.local)"
        $GPOvideOU = if ($GPOvideOU) { "OU=$GPOvideOU,$GPOvideDomaine" } else { $GPOvideDomaine }
        $GPOvidePath = "LDAP://$GPOvideOU"
        $GPOvide = New-GPO -Name $GPOvideName -Description $GPOvideDesc -Domain $GPOvideDomaine -Server $GPOvidePath
        if ($GPOvide) {
            Write-Host "GPO vide '$GPOvideName' créée avec succès dans l'OU '$GPOvideOU'." -ForegroundColor Green
        } else {
            Write-Host "Échec de la création de la GPO vide." -ForegroundColor Red
        }
        Write-Host "Configuration des paramètres de la GPO $GPOvideName" -ForegroundColor Yellow
        Write-Host "Vous pouvez maintenant configurer cette GPO selon vos besoins." -ForegroundColor Green
        $GPOvideKey = Read-Host "Liens vers la clé de registre lier pour configurer la GPO vide (exemple : HKLM\Software\Policies\Microsoft\Windows\ExampleKey)"
        $GPOvideValueName = Read-Host "Nom de la valeur à configurer (exemple : ExampleValue)"
        $GPOvideValueType = Read-Host "Type de la valeur (String, DWord, etc.)"
        $GPOvideValueData = Read-Host "Données de la valeur (exemple : ExampleData)"
        Set-GPRegistryValue -Name $GPOvideName -Key $GPOvideKey -ValueName $GPOvideValueName -Type $GPOvideValueType -Value $GPOvideValueData
        Write-Host "D'autre configuration de registre ? (O/N)" -ForegroundColor Yellow
        $addMore = Read-Host "Votre choix"
        while ($addMore -eq "O") {
            $GPOvideKey = Read-Host "Liens vers la clé de registre lier pour configurer la GPO vide (exemple : HKLM\Software\Policies\Microsoft\Windows\ExampleKey)"
            $GPOvideValueName = Read-Host "Nom de la valeur à configurer (exemple : ExampleValue)"
            $GPOvideValueType = Read-Host "Type de la valeur (String, DWord, etc.)"
            $GPOvideValueData = Read-Host "Données de la valeur (exemple : ExampleData)"
            Set-GPRegistryValue -Name $GPOvideName -Key $GPOvideKey -ValueName $GPOvideValueName -Type $GPOvideValueType -Value $GPOvideValueData
            Write-Host "Configuration de la GPO vide $GPOvideName terminée."
            Write-Host "Souhaitez-vous ajouter une autre configuration de registre ? (O/N)" -ForegroundColor Yellow
            $addMore = Read-Host "Votre choix"
            if ($addMore -ne "O") {
                break
            }
        }
        Write-Host "Configuration de la GPO vide terminée." -ForegroundColor Green
    }
}
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