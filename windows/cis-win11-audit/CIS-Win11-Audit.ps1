<#
.SYNOPSIS
    Audita (y opcionalmente remedia) un conjunto de controles de endurecimiento de
    Windows 11 alineados con el nivel 1 (Level 1) de los CIS Benchmarks.

.DESCRIPTION
    Este script NO reproduce el texto oficial del documento CIS Benchmark for
    Windows 11 (que es propiedad del Center for Internet Security y requiere
    descarga/membresia para consultar la numeracion y redaccion exacta de cada
    control). En su lugar, implementa un conjunto de configuraciones de
    endurecimiento ampliamente reconocidas y documentadas por Microsoft que
    corresponden a controles habituales de Nivel 1 (politicas de contrasena,
    bloqueo de cuentas, opciones de seguridad locales, UAC, SMB, RDP, Windows
    Defender, Firewall, politica de auditoria, AutoPlay, logging de PowerShell).

    Antes de usarlo en produccion o para una certificacion formal, compara el
    campo "Reference" de cada control contra el PDF oficial del benchmark
    (CIS-CAT o CIS SecureSuite) para tu version exacta de Windows 11 y ajusta
    numeracion/alcance segun corresponda.

.PARAMETER Remediate
    Si se especifica, por cada control que NO cumpla se preguntara si se desea
    aplicar la remediacion (Y/N/A=todos/S=omitir todos/Q=salir).

.PARAMETER OutputPath
    Carpeta donde se generaran los reportes CSV y JSON. Por defecto se crea una
    subcarpeta "CIS-Win11-Report_<timestamp>" junto al script.

.PARAMETER Force
    En combinacion con -Remediate, aplica todas las remediaciones sin preguntar
    (equivalente a responder "A" a la primera pregunta). Usar con precaucion.

.EXAMPLE
    .\CIS-Win11-Audit.ps1
    Solo audita y genera el reporte CSV/JSON.

.EXAMPLE
    .\CIS-Win11-Audit.ps1 -Remediate
    Audita y pregunta, control por control, si se debe remediar.

.EXAMPLE
    .\CIS-Win11-Audit.ps1 -Remediate -Force
    Audita y remedia automaticamente todo lo que no cumpla (sin preguntar).

.NOTES
    - Ejecutar como Administrador (clic derecho > Ejecutar como administrador,
      o desde una consola PowerShell elevada).
    - Algunos controles requieren reinicio para tener efecto pleno (se marcan
      en la columna RequiresReboot del reporte).
    - Probado conceptualmente para Windows 11; algunos controles tambien
      aplican a Windows 10 / Server, pero el foco es Windows 11 Enterprise/Pro.
#>

[CmdletBinding()]
param(
    [switch]$Remediate,
    [string]$OutputPath,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$script:ApplyAll = [bool]$Force
$script:SkipAll  = $false

#region Utilidades

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$script:IsAdmin = Test-IsAdmin
if (-not $script:IsAdmin) {
    Write-Warning "No se esta ejecutando como Administrador. La auditoria puede mostrar 'Desconocido' en varios controles y la remediacion fallara."
}

function Get-RegValue {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, $Default = $null)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $Default
    }
}

function Set-RegValue {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Value,
        [string]$Type = 'DWord'
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# --- Helpers de politica de seguridad local (secedit) para Account Policies ---

function Export-SecPolicyFile {
    if (-not $script:IsAdmin) { throw "Se requiere sesion de Administrador para leer la politica de seguridad local (secedit)." }
    $tmp = Join-Path $env:TEMP "secpol_$([guid]::NewGuid().Guid).cfg"
    secedit /export /cfg $tmp /quiet | Out-Null
    if (-not (Test-Path $tmp)) { throw "secedit /export fallo (verifica que la consola este elevada)." }
    return $tmp
}

function Get-SecPolicyValue {
    param([Parameter(Mandatory)][string]$Name, [string]$Section = 'System Access')
    $file = Export-SecPolicyFile
    try {
        $content = Get-Content -Path $file
        $inSection = $false
        foreach ($line in $content) {
            if ($line -match '^\[(.+)\]$') { $inSection = ($Matches[1] -eq $Section); continue }
            if ($inSection -and $line -match '^\s*([^=]+?)\s*=\s*(.+)$') {
                if ($Matches[1].Trim() -eq $Name) { return $Matches[2].Trim() }
            }
        }
        return $null
    } finally {
        Remove-Item -Path $file -ErrorAction SilentlyContinue
    }
}

function Set-SecPolicyValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [string]$Section = 'System Access'
    )
    $file = Export-SecPolicyFile
    try {
        $content      = Get-Content -Path $file
        $newContent   = [System.Collections.Generic.List[string]]::new()
        $inSection    = $false
        $sectionSeen  = $false
        $found        = $false

        foreach ($line in $content) {
            if ($line -match '^\[(.+)\]$') {
                if ($inSection -and -not $found) { $newContent.Add("$Name = $Value") }
                $inSection = ($Matches[1] -eq $Section)
                if ($inSection) { $sectionSeen = $true }
                $newContent.Add($line)
                continue
            }
            if ($inSection -and -not $found -and $line -match '^\s*([^=]+?)\s*=\s*(.+)$' -and $Matches[1].Trim() -eq $Name) {
                $newContent.Add("$Name = $Value")
                $found = $true
                continue
            }
            $newContent.Add($line)
        }
        if ($inSection -and -not $found) { $newContent.Add("$Name = $Value") }
        if (-not $sectionSeen) {
            $newContent.Add("[$Section]")
            $newContent.Add("$Name = $Value")
        }

        Set-Content -Path $file -Value $newContent -Encoding Unicode

        $dbPath  = Join-Path $env:TEMP "secedit_$([guid]::NewGuid().Guid).sdb"
        $logPath = Join-Path $env:TEMP "secedit_$([guid]::NewGuid().Guid).log"
        secedit /configure /db $dbPath /cfg $file /areas SECURITYPOLICY /quiet /log $logPath | Out-Null
        Remove-Item -Path $dbPath, $logPath -ErrorAction SilentlyContinue
    } finally {
        Remove-Item -Path $file -ErrorAction SilentlyContinue
    }
}

# --- Helper de auditpol ---

function Get-AuditSubcategoryState {
    param([Parameter(Mandatory)][string]$Subcategory)
    if (-not $script:IsAdmin) { throw "Se requiere sesion de Administrador para leer la politica de auditoria (auditpol)." }
    $out = auditpol /get /subcategory:"$Subcategory" /r 2>$null | ConvertFrom-Csv
    if (-not $out) { throw "auditpol no devolvio resultados para '$Subcategory'." }
    return $out[0].'Inclusion Setting'
}

function Set-AuditSubcategory {
    param([Parameter(Mandatory)][string]$Subcategory, [switch]$Success, [switch]$Failure)
    $args = @('/set', "/subcategory:$Subcategory")
    $args += "/success:$(if ($Success) {'enable'} else {'disable'})"
    $args += "/failure:$(if ($Failure) {'enable'} else {'disable'})"
    auditpol @args | Out-Null
}

function Confirm-Remediation {
    param([string]$Id, [string]$Title)
    if ($script:ApplyAll) { return $true }
    if ($script:SkipAll)  { return $false }
    while ($true) {
        $resp = Read-Host "  Remediar [$Id] '$Title'? (Y=si / N=no / A=todos / S=omitir todos / Q=salir)"
        switch ($resp.ToUpper()) {
            'Y' { return $true }
            'N' { return $false }
            'A' { $script:ApplyAll = $true; return $true }
            'S' { $script:SkipAll  = $true; return $false }
            'Q' { Write-Host "`nInterrumpido por el usuario." -ForegroundColor Yellow; Write-Results; exit }
            default { Write-Host "  Responde Y, N, A, S o Q." -ForegroundColor DarkYellow }
        }
    }
}
#endregion

#region Definicion de controles
$controls = New-Object System.Collections.Generic.List[object]

function Add-Control {
    param(
        [string]$Id, [string]$Category, [string]$Title, [string]$Reference,
        [scriptblock]$Test, [scriptblock]$GetActual, [scriptblock]$Remediate,
        [bool]$RequiresReboot = $false
    )
    $controls.Add([PSCustomObject]@{
        Id = $Id; Category = $Category; Title = $Title; Reference = $Reference
        Test = $Test; GetActual = $GetActual; Remediate = $Remediate
        RequiresReboot = $RequiresReboot
    })
}

# ---------------- Account Policies ----------------
Add-Control -Id 'ACC-01' -Category 'Account Policies' -Title 'Historial de contrasenas >= 24' -Reference '~CIS 1.1.1' `
    -GetActual { Get-SecPolicyValue -Name 'PasswordHistorySize' } `
    -Test { [int](Get-SecPolicyValue -Name 'PasswordHistorySize') -ge 24 } `
    -Remediate { Set-SecPolicyValue -Name 'PasswordHistorySize' -Value '24' }

Add-Control -Id 'ACC-02' -Category 'Account Policies' -Title 'Vigencia maxima de contrasena <= 365 dias (y != 0)' -Reference '~CIS 1.1.2' `
    -GetActual { Get-SecPolicyValue -Name 'MaximumPasswordAge' } `
    -Test { $v = [int](Get-SecPolicyValue -Name 'MaximumPasswordAge'); $v -gt 0 -and $v -le 365 } `
    -Remediate { Set-SecPolicyValue -Name 'MaximumPasswordAge' -Value '365' }

Add-Control -Id 'ACC-03' -Category 'Account Policies' -Title 'Vigencia minima de contrasena >= 1 dia' -Reference '~CIS 1.1.3' `
    -GetActual { Get-SecPolicyValue -Name 'MinimumPasswordAge' } `
    -Test { [int](Get-SecPolicyValue -Name 'MinimumPasswordAge') -ge 1 } `
    -Remediate { Set-SecPolicyValue -Name 'MinimumPasswordAge' -Value '1' }

Add-Control -Id 'ACC-04' -Category 'Account Policies' -Title 'Longitud minima de contrasena >= 14' -Reference '~CIS 1.1.4' `
    -GetActual { Get-SecPolicyValue -Name 'MinimumPasswordLength' } `
    -Test { [int](Get-SecPolicyValue -Name 'MinimumPasswordLength') -ge 14 } `
    -Remediate { Set-SecPolicyValue -Name 'MinimumPasswordLength' -Value '14' }

Add-Control -Id 'ACC-05' -Category 'Account Policies' -Title 'La contrasena debe cumplir requisitos de complejidad' -Reference '~CIS 1.1.5' `
    -GetActual { Get-SecPolicyValue -Name 'PasswordComplexity' } `
    -Test { (Get-SecPolicyValue -Name 'PasswordComplexity') -eq '1' } `
    -Remediate { Set-SecPolicyValue -Name 'PasswordComplexity' -Value '1' }

Add-Control -Id 'ACC-06' -Category 'Account Policies' -Title 'No almacenar contrasenas con cifrado reversible' -Reference '~CIS 1.1.6' `
    -GetActual { Get-SecPolicyValue -Name 'ClearTextPassword' } `
    -Test { (Get-SecPolicyValue -Name 'ClearTextPassword') -eq '0' } `
    -Remediate { Set-SecPolicyValue -Name 'ClearTextPassword' -Value '0' }

Add-Control -Id 'ACC-07' -Category 'Account Policies' -Title 'Umbral de bloqueo de cuenta entre 1 y 5 intentos' -Reference '~CIS 1.2.1' `
    -GetActual { Get-SecPolicyValue -Name 'LockoutBadCount' } `
    -Test { $v = [int](Get-SecPolicyValue -Name 'LockoutBadCount'); $v -ge 1 -and $v -le 5 } `
    -Remediate { Set-SecPolicyValue -Name 'LockoutBadCount' -Value '5' }

Add-Control -Id 'ACC-08' -Category 'Account Policies' -Title 'Duracion de bloqueo de cuenta >= 15 minutos' -Reference '~CIS 1.2.2' `
    -GetActual { Get-SecPolicyValue -Name 'LockoutDuration' } `
    -Test { [int](Get-SecPolicyValue -Name 'LockoutDuration') -ge 15 } `
    -Remediate { Set-SecPolicyValue -Name 'LockoutDuration' -Value '15' }

Add-Control -Id 'ACC-09' -Category 'Account Policies' -Title 'Restablecer contador de bloqueos >= 15 minutos' -Reference '~CIS 1.2.3' `
    -GetActual { Get-SecPolicyValue -Name 'ResetLockoutCount' } `
    -Test { [int](Get-SecPolicyValue -Name 'ResetLockoutCount') -ge 15 } `
    -Remediate { Set-SecPolicyValue -Name 'ResetLockoutCount' -Value '15' }

# ---------------- Local Security Options ----------------
Add-Control -Id 'SEC-01' -Category 'Local Security Options' -Title 'Cuenta de invitado (Guest) deshabilitada' -Reference '~CIS 2.3.1' `
    -GetActual { try { (Get-LocalUser -Name 'Guest' -ErrorAction Stop).Enabled } catch { 'N/A' } } `
    -Test { try { -not (Get-LocalUser -Name 'Guest' -ErrorAction Stop).Enabled } catch { $true } } `
    -Remediate { try { Disable-LocalUser -Name 'Guest' -ErrorAction Stop } catch {} }

Add-Control -Id 'SEC-02' -Category 'Local Security Options' -Title 'Limitar uso de contrasenas en blanco al inicio de sesion en consola' -Reference '~CIS 2.3.1.5' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1) -eq 1 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1 }

Add-Control -Id 'SEC-03' -Category 'Local Security Options' -Title 'No almacenar valores de hash LAN Manager' -Reference '~CIS 2.3.11.7' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 0) -eq 1 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash' 1 }

Add-Control -Id 'SEC-04' -Category 'Local Security Options' -Title 'Nivel de autenticacion LAN Manager: solo NTLMv2, rechazar LM y NTLM' -Reference '~CIS 2.3.11.8' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 0) -ge 5 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel' 5 }

Add-Control -Id 'SEC-05' -Category 'Local Security Options' -Title 'Restringir enumeracion anonima de cuentas SAM' -Reference '~CIS 2.3.10.1' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 0) -eq 1 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM' 1 }

Add-Control -Id 'SEC-06' -Category 'Local Security Options' -Title 'Restringir enumeracion anonima de cuentas y recursos compartidos' -Reference '~CIS 2.3.10.2' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 0) -eq 1 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymous' 1 }

Add-Control -Id 'SEC-07' -Category 'Local Security Options' -Title '"Todos" no incluye a anonimos' -Reference '~CIS 2.3.10.3' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 1) -eq 0 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 0 }

# ---------------- UAC ----------------
$uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Add-Control -Id 'UAC-01' -Category 'User Account Control' -Title 'UAC: ejecutar en Modo de aprobacion de administrador' -Reference '~CIS 2.3.17.1' `
    -GetActual { Get-RegValue $uacPath 'EnableLUA' } `
    -Test { (Get-RegValue $uacPath 'EnableLUA' 0) -eq 1 } `
    -Remediate { Set-RegValue $uacPath 'EnableLUA' 1 } -RequiresReboot $true

Add-Control -Id 'UAC-02' -Category 'User Account Control' -Title 'UAC: pedir consentimiento en el escritorio seguro para administradores' -Reference '~CIS 2.3.17.2' `
    -GetActual { Get-RegValue $uacPath 'ConsentPromptBehaviorAdmin' } `
    -Test { (Get-RegValue $uacPath 'ConsentPromptBehaviorAdmin' 0) -eq 2 } `
    -Remediate { Set-RegValue $uacPath 'ConsentPromptBehaviorAdmin' 2 }

Add-Control -Id 'UAC-03' -Category 'User Account Control' -Title 'UAC: cambiar al escritorio seguro al solicitar elevacion' -Reference '~CIS 2.3.17.5' `
    -GetActual { Get-RegValue $uacPath 'PromptOnSecureDesktop' } `
    -Test { (Get-RegValue $uacPath 'PromptOnSecureDesktop' 0) -eq 1 } `
    -Remediate { Set-RegValue $uacPath 'PromptOnSecureDesktop' 1 }

Add-Control -Id 'UAC-04' -Category 'User Account Control' -Title 'UAC: aplicar Modo de aprobacion de administrador a la cuenta Administrador integrada' -Reference '~CIS 2.3.17.3' `
    -GetActual { Get-RegValue $uacPath 'FilterAdministratorToken' } `
    -Test { (Get-RegValue $uacPath 'FilterAdministratorToken' 0) -eq 1 } `
    -Remediate { Set-RegValue $uacPath 'FilterAdministratorToken' 1 } -RequiresReboot $true

# ---------------- Red ----------------
Add-Control -Id 'NET-01' -Category 'Network' -Title 'Protocolo SMBv1 deshabilitado' -Reference '~CIS 18.3.1' `
    -GetActual { try { (Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop).State } catch { 'N/A' } } `
    -Test { try { (Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop).State -eq 'Disabled' } catch { $true } } `
    -Remediate { Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart -ErrorAction SilentlyContinue | Out-Null } -RequiresReboot $true

Add-Control -Id 'NET-02' -Category 'Network' -Title 'Firma SMB requerida (cliente)' -Reference '~CIS 2.3.9.2' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 0) -eq 1 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1 }

Add-Control -Id 'NET-03' -Category 'Network' -Title 'Firma SMB requerida (servidor)' -Reference '~CIS 2.3.9.1' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 0) -eq 1 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 1 }

Add-Control -Id 'NET-04' -Category 'Network' -Title 'LLMNR (resolucion de nombres multicast) deshabilitado' -Reference '~CIS 18.6.4.1' `
    -GetActual { Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' } `
    -Test { (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 1) -eq 0 } `
    -Remediate { Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 }

Add-Control -Id 'NET-05' -Category 'Network' -Title 'WDigest: no mantener credenciales de logon en texto plano en memoria' -Reference '~CIS 18.3.2' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 1) -eq 0 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 }

Add-Control -Id 'NET-06' -Category 'Network' -Title 'Escritorio remoto (RDP) requiere autenticacion a nivel de red (NLA)' -Reference '~CIS 18.9.65.3' `
    -GetActual { Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' } `
    -Test { (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 0) -eq 1 } `
    -Remediate { Set-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1 }

# ---------------- Windows Defender / Firewall ----------------
Add-Control -Id 'DEF-01' -Category 'Windows Defender' -Title 'Proteccion en tiempo real habilitada' -Reference '~CIS 18.9.47' `
    -GetActual { try { -not (Get-MpPreference).DisableRealtimeMonitoring } catch { 'N/A' } } `
    -Test { try { -not (Get-MpPreference).DisableRealtimeMonitoring } catch { $false } } `
    -Remediate { try { Set-MpPreference -DisableRealtimeMonitoring $false } catch {} }

Add-Control -Id 'DEF-02' -Category 'Windows Defender' -Title 'Proteccion contra aplicaciones potencialmente no deseadas (PUA) habilitada' -Reference '~CIS 18.9.47' `
    -GetActual { try { (Get-MpPreference).PUAProtection } catch { 'N/A' } } `
    -Test { try { (Get-MpPreference).PUAProtection -ne 0 } catch { $false } } `
    -Remediate { try { Set-MpPreference -PUAProtection Enabled } catch {} }

Add-Control -Id 'FW-01' -Category 'Windows Firewall' -Title 'Firewall de Windows habilitado en los 3 perfiles' -Reference '~CIS 9.1/9.2/9.3' `
    -GetActual { try { (Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join '; ' } catch { 'N/A' } } `
    -Test { try { -not (Get-NetFirewallProfile | Where-Object { -not $_.Enabled }) } catch { $false } } `
    -Remediate { try { Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True } catch {} }

# ---------------- Politica de auditoria ----------------
Add-Control -Id 'AUD-01' -Category 'Audit Policy' -Title 'Auditar validacion de credenciales (exito y error)' -Reference '~CIS 17.1.1' `
    -GetActual { Get-AuditSubcategoryState -Subcategory 'Credential Validation' } `
    -Test { (Get-AuditSubcategoryState -Subcategory 'Credential Validation') -eq 'Success and Failure' } `
    -Remediate { Set-AuditSubcategory -Subcategory 'Credential Validation' -Success -Failure }

Add-Control -Id 'AUD-02' -Category 'Audit Policy' -Title 'Auditar administracion de cuentas de usuario (exito y error)' -Reference '~CIS 17.2.4' `
    -GetActual { Get-AuditSubcategoryState -Subcategory 'User Account Management' } `
    -Test { (Get-AuditSubcategoryState -Subcategory 'User Account Management') -eq 'Success and Failure' } `
    -Remediate { Set-AuditSubcategory -Subcategory 'User Account Management' -Success -Failure }

Add-Control -Id 'AUD-03' -Category 'Audit Policy' -Title 'Auditar inicio de sesion (exito y error)' -Reference '~CIS 17.5.1' `
    -GetActual { Get-AuditSubcategoryState -Subcategory 'Logon' } `
    -Test { (Get-AuditSubcategoryState -Subcategory 'Logon') -eq 'Success and Failure' } `
    -Remediate { Set-AuditSubcategory -Subcategory 'Logon' -Success -Failure }

Add-Control -Id 'AUD-04' -Category 'Audit Policy' -Title 'Auditar inicio de sesion especial (exito)' -Reference '~CIS 17.5.4' `
    -GetActual { Get-AuditSubcategoryState -Subcategory 'Special Logon' } `
    -Test { (Get-AuditSubcategoryState -Subcategory 'Special Logon') -in @('Success', 'Success and Failure') } `
    -Remediate { Set-AuditSubcategory -Subcategory 'Special Logon' -Success }

# ---------------- Otros ----------------
Add-Control -Id 'MISC-01' -Category 'Misc' -Title 'AutoPlay/AutoRun deshabilitado para todas las unidades' -Reference '~CIS 18.9.8.1' `
    -GetActual { Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' } `
    -Test { (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 0) -eq 255 } `
    -Remediate { Set-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 }

Add-Control -Id 'MISC-02' -Category 'Misc' -Title 'PowerShell Script Block Logging habilitado' -Reference '~CIS 18.9.100.1' `
    -GetActual { Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' } `
    -Test { (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 0) -eq 1 } `
    -Remediate { Set-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 }

#endregion

#region Ejecucion
$results = New-Object System.Collections.Generic.List[object]

function Write-Results {
    if (-not $OutputPath) {
        $ts = Get-Date -Format 'yyyyMMdd_HHmmss'
        $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $script:OutputPath = Join-Path $baseDir "CIS-Win11-Report_$ts"
    }
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

    $csvPath  = Join-Path $OutputPath 'CIS-Win11-Results.csv'
    $jsonPath = Join-Path $OutputPath 'CIS-Win11-Results.json'

    $results | Select-Object Id, Category, Title, Reference, Status, Actual, RemediationApplied, RequiresReboot, Error |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $results | Select-Object Id, Category, Title, Reference, Status, Actual, RemediationApplied, RequiresReboot, Error |
        ConvertTo-Json -Depth 4 | Set-Content -Path $jsonPath -Encoding UTF8

    Write-Host "`nReportes generados:" -ForegroundColor Cyan
    Write-Host "  CSV : $csvPath"
    Write-Host "  JSON: $jsonPath"
}

Write-Host "=== Auditoria CIS-aligned Windows 11 (Nivel 1) ===" -ForegroundColor Cyan
Write-Host "Modo remediacion: $(if ($Remediate) {'ACTIVADO'} else {'desactivado (solo auditoria)'})`n"

foreach ($c in $controls) {
    Write-Host -NoNewline ("[{0,-8}] {1,-70}" -f $c.Id, $c.Title)

    $status = 'Unknown'
    $actual = $null
    $errMsg = $null
    $remediationApplied = $false

    try {
        $actual = & $c.GetActual
    } catch {
        $actual = "Error: $($_.Exception.Message)"
    }

    try {
        $pass = [bool](& $c.Test)
        $status = if ($pass) { 'Pass' } else { 'Fail' }
    } catch {
        $status = 'Error'
        $errMsg = $_.Exception.Message
    }

    switch ($status) {
        'Pass'    { Write-Host " [OK]"       -ForegroundColor Green }
        'Fail'    { Write-Host " [FAIL]"     -ForegroundColor Red }
        'Error'   { Write-Host " [ERROR]"    -ForegroundColor DarkYellow }
        'Unknown' { Write-Host " [DESCONOCIDO]" -ForegroundColor DarkGray }
    }

    if ($status -eq 'Fail' -and $Remediate -and $script:IsAdmin) {
        if (Confirm-Remediation -Id $c.Id -Title $c.Title) {
            try {
                & $c.Remediate
                $remediationApplied = $true
                Write-Host "    -> Remediado." -ForegroundColor Green
                try { $actual = & $c.GetActual } catch {}
            } catch {
                Write-Host "    -> Error al remediar: $($_.Exception.Message)" -ForegroundColor Red
                $errMsg = "Remediation error: $($_.Exception.Message)"
            }
        }
    } elseif ($status -eq 'Fail' -and $Remediate -and -not $script:IsAdmin) {
        Write-Host "    -> Se omite remediacion: se requiere sesion de Administrador." -ForegroundColor DarkYellow
    }

    $results.Add([PSCustomObject]@{
        Id                  = $c.Id
        Category            = $c.Category
        Title               = $c.Title
        Reference           = $c.Reference
        Status              = $status
        Actual              = $actual
        RemediationApplied  = $remediationApplied
        RequiresReboot      = $c.RequiresReboot
        Error               = $errMsg
    })
}

$pass  = ($results | Where-Object Status -eq 'Pass').Count
$fail  = ($results | Where-Object Status -eq 'Fail').Count
$err   = ($results | Where-Object Status -eq 'Error').Count
$unk   = ($results | Where-Object Status -eq 'Unknown').Count
$total = $results.Count
$pct   = if ($total -gt 0) { [math]::Round(($pass / $total) * 100, 1) } else { 0 }

Write-Host "`n=== Resumen ===" -ForegroundColor Cyan
Write-Host "Total: $total | Cumple: $pass | No cumple: $fail | Error: $err | Desconocido: $unk"
Write-Host "Cumplimiento: $pct%"

if (($results | Where-Object { $_.Status -eq 'Fail' -and $_.RemediationApplied -and $_.RequiresReboot }).Count -gt 0) {
    Write-Host "`nAlgunos controles remediados requieren REINICIAR el equipo para tener efecto completo." -ForegroundColor Yellow
}

Write-Results
#endregion
