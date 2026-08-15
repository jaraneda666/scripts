# CIS-RHEL-Audit

Script de Bash para **auditar** (y opcionalmente **remediar**) un conjunto de
configuraciones de endurecimiento de **Red Hat Enterprise Linux (RHEL 9 /
RHEL 10)** alineadas con controles de **Nivel 1** habitualmente cubiertos por
los *CIS Benchmarks*.

Es el equivalente en Bash/Linux del script
[`CIS-Win11-Audit.ps1`](../../windows/cis-win11-audit/) para Windows 11: misma
filosofía (solo auditoría por defecto, remediación interactiva opcional,
reporte CSV/JSON), adaptada a las herramientas nativas de RHEL
(`sysctl`, `sshd -T`, `authselect`/`pam_faillock`, `systemctl`, `auditd`,
`firewalld`, SELinux).

## ⚠️ Aviso importante sobre alcance y CIS

Este script **no reproduce el texto ni la numeración oficial** del documento
*CIS Benchmark for Red Hat Enterprise Linux*, que es propiedad del
[Center for Internet Security (CIS)](https://www.cisecurity.org/) y requiere
descarga o membresía (CIS SecureSuite) para consultarlo en detalle.

En su lugar, implementa un conjunto de configuraciones de endurecimiento
**ampliamente documentadas por Red Hat y la comunidad** que corresponden a
controles habituales de Nivel 1: módulos de kernel innecesarios, parámetros
de red (`sysctl`), SSH, políticas de contraseña, cuentas, `pam_faillock`,
auditoría (`auditd`/`rsyslog`/`journald`), SELinux, `firewalld`,
sincronización de tiempo (`chronyd`), permisos de archivos críticos y
servicios innecesarios.

Cada control incluye una columna `Reference` con una referencia
**aproximada** (`~CIS x.x.x`). **Si necesitas un mapeo exacto para una
auditoría formal o una certificación de cumplimiento, coteja cada control
contra el PDF oficial del benchmark** (vía CIS-CAT Pro o CIS SecureSuite)
para tu versión exacta de RHEL y ajusta numeración/alcance según
corresponda.

Este proyecto no está afiliado, respaldado ni certificado por CIS ni por
Red Hat.

## ¿Qué hace?

- Evalúa **36 controles** de Nivel 1 organizados en 11 categorías (ver tabla
  abajo).
- Por defecto **solo audita**: no modifica nada en el sistema.
- Con `--remediate`, por cada control que **no cumple y tiene remediación
  automática disponible**, pregunta si se debe corregir (`Y`/`N`/`A`=todos/
  `S`=omitir todos/`Q`=salir).
- Con `--remediate --force`, aplica automáticamente todas las remediaciones
  disponibles sin preguntar (úsalo solo si ya revisaste el resultado de una
  auditoría previa).
- Genera un reporte en **CSV** y **JSON** con el resultado de cada control.
- Detecta la distribución vía `/etc/os-release` y advierte si no es RHEL.

## Requisitos

- **RHEL 9.x o RHEL 10.x** (diseñado y pensado para estas versiones; no
  probado en RHEL 7/8 ni en derivados como Rocky/Alma, aunque varios
  controles deberían comportarse igual).
- Bash 4+ (incluido por defecto en RHEL).
- Utilidades estándar del sistema: `awk`, `sed`, `grep`, `systemctl`,
  `sysctl`, `stat`. Algunos controles usan `sshd -T`, `authselect`,
  `getenforce`/`setenforce`, `modprobe`/`lsmod`.
- **Ejecutar como root** (`sudo`). Sin privilegios de root:
  - Los controles que requieren leer `/etc/shadow`, ejecutar `sshd -T` con
    el detalle completo, o consultar servicios vía `systemctl` en algunos
    entornos, mostrarán `Error` con un mensaje explícito.
  - La remediación de cualquier control se omite automáticamente si no se
    ejecuta como root.

## Uso

Clona el repositorio o descarga el script, y desde una sesión con `sudo` /
root:

```bash
cd linux/cis-rhel-audit
chmod +x CIS-RHEL-Audit.sh

# Solo auditar (no modifica nada)
sudo ./CIS-RHEL-Audit.sh

# Auditar y remediar, preguntando control por control
sudo ./CIS-RHEL-Audit.sh --remediate

# Auditar y remediar TODO automáticamente, sin preguntar (usar con cuidado)
sudo ./CIS-RHEL-Audit.sh --remediate --force

# Especificar carpeta de salida para los reportes
sudo ./CIS-RHEL-Audit.sh --output-path /var/tmp/cis-report
```

### Parámetros

| Parámetro          | Descripción                                                                                     |
|---------------------|---------------------------------------------------------------------------------------------------|
| `--remediate`       | Habilita la remediación interactiva de los controles que fallen y tengan remediación disponible.  |
| `--force`           | Junto con `--remediate`, aplica todas las remediaciones sin preguntar.                            |
| `--output-path DIR` | Carpeta donde se generan los reportes. Por defecto crea `CIS-RHEL-Report_<timestamp>` junto al script. |
| `-h`, `--help`      | Muestra la ayuda.                                                                                  |

### Durante la remediación interactiva

Por cada control que falle y tenga remediación automática, si usas
`--remediate` (sin `--force`) se te preguntará:

```
Remediar [SSH-01] 'PermitRootLogin deshabilitado'? (Y=si / N=no / A=todos / S=omitir todos / Q=salir):
```

- `Y` – remedia solo este control.
- `N` – omite solo este control.
- `A` – remedia este y todos los siguientes sin volver a preguntar.
- `S` – omite este y todos los siguientes sin volver a preguntar.
- `Q` – detiene la ejecución, genera el reporte con lo evaluado hasta el momento y sale.

Algunos controles (ver tabla, columna "Remediación") **no tienen
remediación automática** porque requieren una decisión humana (por ejemplo,
qué hacer con una cuenta que tiene UID 0 además de `root`). En esos casos el
script solo audita y deja constancia en el reporte.

## Salida / reportes

Al finalizar, se generan dos archivos dentro de la carpeta de salida:

- `CIS-RHEL-Results.csv`
- `CIS-RHEL-Results.json`

Ambos contienen, por cada control:

| Campo                | Descripción                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| `Id`                  | Identificador corto del control (ej. `SSH-01`).                            |
| `Category`            | Categoría (Network, SSH, Password Policy, etc.).                           |
| `Title`               | Descripción del control.                                                   |
| `Reference`           | Referencia aproximada al CIS Benchmark (`~CIS x.x.x`), a validar manualmente. |
| `Status`              | `PASS`, `FAIL`, `ERROR` o `Unknown`.                                        |
| `Actual`              | Valor actual detectado en el sistema.                                      |
| `RemediationApplied`  | `true`/`false` — si se aplicó una corrección en esta ejecución.            |
| `RequiresReboot`      | `true`/`false` — si el control remediado requiere reinicio para surtir efecto completo. |
| `Error`               | Mensaje de error, si lo hubo (ej. falta de privilegios, comando no disponible). |

**Nota:** estos reportes contienen información del estado de seguridad del
equipo auditado. El `.gitignore` del repositorio ya excluye las carpetas
`CIS-RHEL-Report_*` para evitar subirlos por error a control de versiones.

## Controles evaluados

| Id | Categoría | Control | Remediación |
|----|-----------|---------|:---:|
| FS-01 | Filesystem | Módulo de kernel `cramfs` deshabilitado | ✅ |
| FS-02 | Filesystem | Módulo de kernel `freevxfs` deshabilitado | ✅ |
| NET-01 | Network | Reenvío de paquetes IP (forwarding) deshabilitado | ✅ |
| NET-02 | Network | Rechazar paquetes con ruta de origen (source routed) | ✅ |
| NET-03 | Network | Ignorar redirecciones ICMP entrantes | ✅ |
| NET-04 | Network | No enviar redirecciones ICMP | ✅ |
| NET-05 | Network | Registrar paquetes "martian" (`log_martians`) | ✅ |
| NET-06 | Network | Ignorar solicitudes ICMP a direcciones broadcast | ✅ |
| NET-07 | Network | TCP SYN cookies habilitado | ✅ |
| NET-08 | Network | No aceptar router advertisements IPv6 | ✅ |
| SSH-01 | SSH | `PermitRootLogin` deshabilitado | ✅ |
| SSH-02 | SSH | Autenticación con contraseña vacía deshabilitada | ✅ |
| SSH-03 | SSH | `X11Forwarding` deshabilitado | ✅ |
| SSH-04 | SSH | `MaxAuthTries` <= 4 | ✅ |
| SSH-05 | SSH | `ClientAliveInterval` configurado (1-300s) | ✅ |
| SSH-06 | SSH | Banner de aviso legal configurado | ✅ |
| SSH-07 | SSH | `LoginGraceTime` <= 60s | ✅ |
| PWD-01 | Password Policy | Vigencia máxima de contraseña <= 365 días | ✅ |
| PWD-02 | Password Policy | Vigencia mínima de contraseña >= 1 día | ✅ |
| PWD-03 | Password Policy | Advertencia de expiración >= 7 días | ✅ |
| PWD-04 | Password Policy | Longitud mínima (`pwquality` `minlen`) >= 14 | ✅ |
| PWD-05 | Password Policy | Complejidad mínima (`minclass`) >= 4 clases | ✅ |
| ACC-01 | Accounts | Ninguna cuenta aparte de `root` tiene UID 0 | ❌ manual |
| ACC-02 | Accounts | Ninguna cuenta con contraseña vacía | ✅ (bloquea la cuenta) |
| ACC-03 | Accounts | Bloqueo de cuenta tras intentos fallidos (`pam_faillock`, deny 1-5) | ✅ |
| ACC-04 | Accounts | `UMASK` por defecto 027 o más restrictivo | ✅ |
| AUD-01 | Audit Logging | Servicio `auditd` habilitado y activo | ✅ |
| AUD-02 | Audit Logging | Logging centralizado/persistente (`rsyslog` o `journald`) | ✅ |
| SEL-01 | SELinux | SELinux en modo `Enforcing` | ✅ |
| FW-01 | Firewall | `firewalld` habilitado y activo | ✅ |
| TIME-01 | Time Sync | `chronyd` habilitado y activo | ✅ |
| PERM-01 | File Permissions | `/etc/passwd` con permisos 644 o más restrictivo, `root:root` | ✅ |
| PERM-02 | File Permissions | `/etc/shadow` sin permisos directos (0000), `root:root` | ✅ |
| PERM-03 | File Permissions | `/etc/gshadow` sin permisos directos (0000), `root:root` | ✅ |
| SVC-01 | Services | `avahi-daemon` no instalado o deshabilitado | ✅ |
| SVC-02 | Services | `cups` no instalado o deshabilitado | ✅ |

## Reinicio requerido

Solo `SEL-01` (cambio de SELinux a `Enforcing` cuando estaba en modo
`Permissive`/`Disabled`) se marca con `RequiresReboot = true`, ya que un
cambio completo del modo SELinux (especialmente si estaba `Disabled`)
generalmente requiere un reetiquetado de archivos y reinicio para aplicarse
de forma completa y consistente. El resto de las remediaciones surten
efecto inmediato (`sysctl -w`, recarga de `sshd`, `systemctl enable --now`,
etc.).

## Limitaciones conocidas

- No cubre controles de Nivel 2 ni áreas como particionado dedicado de
  `/tmp`, `/var`, `/var/log` con opciones `nodev`/`nosuid`/`noexec`, AIDE
  (integridad de archivos), Kdump, o políticas de cifrado a nivel de disco
  — quedan fuera del alcance actual por ser altamente dependientes del
  esquema de particionado y disruptivas de automatizar de forma segura.
- `ACC-01` (cuentas con UID 0 además de `root`) es **solo auditoría**: no
  existe una remediación automática segura de aplicar sin contexto humano.
- `pam_faillock` (`ACC-03`) se gestiona de forma distinta según el perfil de
  `authselect` activo; en RHEL 9/10 el feature `with-faillock` suele venir
  habilitado por defecto en los perfiles estándar, pero en instalaciones
  con perfiles personalizados el control puede requerir ajuste manual del
  perfil de `authselect` además de `/etc/security/faillock.conf`.
- El control de banner SSH (`SSH-06`) crea `/etc/issue.net` con un mensaje
  genérico si no existe; personaliza su contenido según la política legal
  de tu organización.

## Contribuir

Los *pull requests* son bienvenidos, especialmente para:

- Agregar controles adicionales de Nivel 1 o Nivel 2.
- Corregir referencias `Reference` contra la numeración oficial verificada
  de una versión específica del benchmark.
- Ampliar la cobertura a RHEL 8 o a derivados compatibles (Rocky Linux,
  AlmaLinux, CentOS Stream).

## Licencia

Este script se distribuye bajo la [licencia MIT](../../LICENSE) del
repositorio.
