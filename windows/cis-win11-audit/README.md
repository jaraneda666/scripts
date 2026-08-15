# CIS-Win11-Audit

Script de PowerShell para **auditar** (y opcionalmente **remediar**) un conjunto de
configuraciones de endurecimiento de **Windows 11** alineadas con controles de
**Nivel 1** habitualmente cubiertos por los *CIS Benchmarks*.

## ⚠️ Aviso importante sobre alcance y CIS

Este script **no reproduce el texto ni la numeración oficial** del documento
*CIS Benchmark for Microsoft Windows 11*, que es propiedad del
[Center for Internet Security (CIS)](https://www.cisecurity.org/) y requiere
descarga o membresía (CIS SecureSuite) para consultarlo en detalle.

En su lugar, implementa un conjunto de configuraciones de endurecimiento
**ampliamente documentadas por Microsoft** que corresponden a controles
habituales de Nivel 1: políticas de contraseña y bloqueo de cuenta, opciones
de seguridad locales, UAC, SMB/RDP/LLMNR/WDigest, Windows Defender, Firewall,
política de auditoría, AutoPlay y logging de PowerShell.

Cada control incluye una columna `Reference` con una referencia **aproximada**
(`~CIS x.x.x`). **Si necesitas un mapeo exacto para una auditoría formal o una
certificación de cumplimiento, coteja cada control contra el PDF oficial del
benchmark** (vía CIS-CAT Pro o CIS SecureSuite) para tu versión exacta de
Windows 11 y ajusta numeración/alcance según corresponda.

Este proyecto no está afiliado, respaldado ni certificado por CIS.

## ¿Qué hace?

- Evalúa **35 controles** de Nivel 1 organizados en 8 categorías (ver tabla
  abajo).
- Por defecto **solo audita**: no modifica nada en el sistema.
- Con `-Remediate`, por cada control que **no cumple** pregunta si se debe
  corregir (`Y`/`N`/`A`=todos/`S`=omitir todos/`Q`=salir).
- Con `-Remediate -Force`, aplica automáticamente todas las remediaciones sin
  preguntar (úsalo solo si ya revisaste el resultado de una auditoría previa).
- Genera un reporte en **CSV** y **JSON** con el resultado de cada control.

## Requisitos

- Windows 11 (también funciona en gran parte sobre Windows 10 / Server, pero
  no está pensado ni probado para eso).
- PowerShell 5.1 o superior (incluido en Windows) o PowerShell 7+.
- **Ejecutar como Administrador.** Sin privilegios elevados:
  - Los controles que dependen de `secedit` (políticas de contraseña /
    bloqueo de cuenta) y `auditpol` (política de auditoría) fallarán con el
    estado `Error` y un mensaje explícito pidiendo elevación.
  - El resto de los controles (registro, Windows Defender, Firewall, etc.) sí
    pueden auditarse sin privilegios elevados, pero **no remediarse**.
- Módulo `Microsoft.PowerShell.LocalAccounts` disponible (viene por defecto)
  para el control de la cuenta Guest.

## Uso

Clona el repositorio o descarga el script, y desde una consola de PowerShell
**ejecutada como Administrador**:

```powershell
cd windows\cis-win11-audit

# Solo auditar (no modifica nada)
.\CIS-Win11-Audit.ps1

# Auditar y remediar, preguntando control por control
.\CIS-Win11-Audit.ps1 -Remediate

# Auditar y remediar TODO automáticamente, sin preguntar (usar con cuidado)
.\CIS-Win11-Audit.ps1 -Remediate -Force

# Especificar carpeta de salida para los reportes
.\CIS-Win11-Audit.ps1 -OutputPath "C:\Reportes\CIS"
```

Si tu política de ejecución bloquea el script, ejecútalo así (solo para esta
sesión, no cambia la política del sistema):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\CIS-Win11-Audit.ps1
```

### Parámetros

| Parámetro     | Tipo   | Descripción                                                                                   |
|---------------|--------|------------------------------------------------------------------------------------------------|
| `-Remediate`  | switch | Habilita la remediación interactiva de los controles que fallen.                              |
| `-Force`      | switch | Junto con `-Remediate`, aplica todas las remediaciones sin preguntar (equivale a responder "A" desde el inicio). |
| `-OutputPath` | string | Carpeta donde se generan los reportes. Por defecto crea `CIS-Win11-Report_<timestamp>` junto al script. |

### Durante la remediación interactiva

Por cada control que falle, si usas `-Remediate` (sin `-Force`) se te preguntará:

```
Remediar [SEC-06] 'Restringir enumeracion anonima de cuentas y recursos compartidos'? (Y=si / N=no / A=todos / S=omitir todos / Q=salir)
```

- `Y` – remedia solo este control.
- `N` – omite solo este control.
- `A` – remedia este y todos los siguientes sin volver a preguntar.
- `S` – omite este y todos los siguientes sin volver a preguntar.
- `Q` – detiene la ejecución, genera el reporte con lo evaluado hasta el momento y sale.

## Salida / reportes

Al finalizar, se generan dos archivos dentro de la carpeta de salida:

- `CIS-Win11-Results.csv`
- `CIS-Win11-Results.json`

Ambos contienen, por cada control:

| Campo                | Descripción                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `Id`                  | Identificador corto del control (ej. `ACC-04`).                            |
| `Category`            | Categoría (Account Policies, UAC, Network, etc.).                          |
| `Title`               | Descripción del control.                                                   |
| `Reference`           | Referencia aproximada al CIS Benchmark (`~CIS x.x.x`), a validar manualmente. |
| `Status`              | `Pass`, `Fail`, `Error` o `Unknown`.                                        |
| `Actual`              | Valor actual detectado en el sistema.                                      |
| `RemediationApplied`  | `True`/`False` — si se aplicó una corrección en esta ejecución.            |
| `RequiresReboot`      | `True`/`False` — si el control remediado requiere reinicio para surtir efecto completo. |
| `Error`               | Mensaje de error, si lo hubo (ej. falta de privilegios).                   |

**Nota:** estos reportes contienen información del estado de seguridad del
equipo auditado. El `.gitignore` del repositorio ya excluye las carpetas
`CIS-Win11-Report_*` para evitar subirlos por error a control de versiones.

## Controles evaluados

| Id | Categoría | Control |
|----|-----------|---------|
| ACC-01 | Account Policies | Historial de contraseñas >= 24 |
| ACC-02 | Account Policies | Vigencia máxima de contraseña <= 365 días (y != 0) |
| ACC-03 | Account Policies | Vigencia mínima de contraseña >= 1 día |
| ACC-04 | Account Policies | Longitud mínima de contraseña >= 14 |
| ACC-05 | Account Policies | La contraseña debe cumplir requisitos de complejidad |
| ACC-06 | Account Policies | No almacenar contraseñas con cifrado reversible |
| ACC-07 | Account Policies | Umbral de bloqueo de cuenta entre 1 y 5 intentos |
| ACC-08 | Account Policies | Duración de bloqueo de cuenta >= 15 minutos |
| ACC-09 | Account Policies | Restablecer contador de bloqueos >= 15 minutos |
| SEC-01 | Local Security Options | Cuenta de invitado (Guest) deshabilitada |
| SEC-02 | Local Security Options | Limitar uso de contraseñas en blanco al inicio de sesión en consola |
| SEC-03 | Local Security Options | No almacenar valores de hash LAN Manager |
| SEC-04 | Local Security Options | Nivel de autenticación LAN Manager: solo NTLMv2 |
| SEC-05 | Local Security Options | Restringir enumeración anónima de cuentas SAM |
| SEC-06 | Local Security Options | Restringir enumeración anónima de cuentas y recursos compartidos |
| SEC-07 | Local Security Options | "Todos" no incluye a anónimos |
| UAC-01 | User Account Control | UAC: ejecutar en Modo de aprobación de administrador |
| UAC-02 | User Account Control | UAC: pedir consentimiento en el escritorio seguro para administradores |
| UAC-03 | User Account Control | UAC: cambiar al escritorio seguro al solicitar elevación |
| UAC-04 | User Account Control | UAC: aplicar Modo de aprobación a la cuenta Administrador integrada |
| NET-01 | Network | Protocolo SMBv1 deshabilitado |
| NET-02 | Network | Firma SMB requerida (cliente) |
| NET-03 | Network | Firma SMB requerida (servidor) |
| NET-04 | Network | LLMNR deshabilitado |
| NET-05 | Network | WDigest: no mantener credenciales en texto plano en memoria |
| NET-06 | Network | RDP requiere autenticación a nivel de red (NLA) |
| DEF-01 | Windows Defender | Protección en tiempo real habilitada |
| DEF-02 | Windows Defender | Protección contra aplicaciones potencialmente no deseadas (PUA) |
| FW-01 | Windows Firewall | Firewall habilitado en los 3 perfiles |
| AUD-01 | Audit Policy | Auditar validación de credenciales (éxito y error) |
| AUD-02 | Audit Policy | Auditar administración de cuentas de usuario (éxito y error) |
| AUD-03 | Audit Policy | Auditar inicio de sesión (éxito y error) |
| AUD-04 | Audit Policy | Auditar inicio de sesión especial (éxito) |
| MISC-01 | Misc | AutoPlay/AutoRun deshabilitado para todas las unidades |
| MISC-02 | Misc | PowerShell Script Block Logging habilitado |

## Reinicio requerido

Algunos controles remediados solo surten efecto completo tras reiniciar el
equipo (marcados con `RequiresReboot = True` en el reporte), por ejemplo:

- `UAC-01` (EnableLUA)
- `UAC-04` (FilterAdministratorToken)
- `NET-01` (deshabilitar SMBv1)

Si el script aplicó alguna remediación de este tipo, lo indicará al final de
la ejecución.

## Limitaciones conocidas

- No cubre controles de Nivel 2 (más estrictos, con mayor impacto en
  funcionalidad) ni áreas como BitLocker, Credential Guard, Attack Surface
  Reduction (ASR) de Defender, o plantillas de seguridad completas — quedan
  fuera del alcance actual.
- Los controles `AUD-*` requieren que el subsistema de auditoría esté en modo
  "Advanced Audit Policy" (comportamiento por defecto en Windows 11 moderno).
- El renombrado de las cuentas Administrador/Guest (control clásico de CIS)
  no se audita ni remedia automáticamente por ser altamente disruptivo en
  entornos con automatización que dependa del nombre de cuenta.

## Contribuir

Los *pull requests* son bienvenidos, especialmente para:

- Agregar controles adicionales de Nivel 1 o Nivel 2.
- Corregir referencias `Reference` contra la numeración oficial verificada
  de una versión específica del benchmark.
- Mejorar la cobertura de pruebas en distintas ediciones de Windows 11
  (Home / Pro / Enterprise).

## Licencia

Este script se distribuye bajo la [licencia MIT](../../LICENSE) del
repositorio.
