#!/usr/bin/env bash
#
# CIS-RHEL-Audit.sh
#
# Audita (y opcionalmente remedia) un conjunto de configuraciones de
# endurecimiento de Red Hat Enterprise Linux (RHEL 9 / RHEL 10) alineadas
# con controles de Nivel 1 habitualmente cubiertos por los CIS Benchmarks.
#
# Este script NO reproduce el texto ni la numeracion oficial del CIS
# Benchmark for Red Hat Enterprise Linux (propiedad del Center for Internet
# Security, requiere descarga/membresia). Ver README.md de esta carpeta.
#
# Uso:
#   sudo ./CIS-RHEL-Audit.sh [--remediate] [--force] [--output-path DIR] [-h|--help]
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Configuracion / argumentos
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMEDIATE=0
FORCE=0
OUTPUT_PATH=""
APPLY_ALL=0
SKIP_ALL=0

print_usage() {
    cat <<EOF
Uso: $0 [opciones]

Opciones:
  --remediate          Pregunta, control por control, si se debe remediar
                        cada control que no cumpla.
  --force              Junto con --remediate, aplica todas las remediaciones
                        sin preguntar. Usar con precaucion.
  --output-path DIR     Carpeta donde se generan los reportes CSV/JSON.
                        Por defecto: ./CIS-RHEL-Report_<timestamp>
  -h, --help            Muestra esta ayuda.

Ejemplos:
  sudo $0
  sudo $0 --remediate
  sudo $0 --remediate --force
  sudo $0 --output-path /var/tmp/cis-report
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --remediate) REMEDIATE=1; shift ;;
        --force) FORCE=1; shift ;;
        --output-path) OUTPUT_PATH="${2:-}"; shift 2 ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo "Opcion desconocida: $1" >&2; print_usage; exit 1 ;;
    esac
done
[[ $FORCE -eq 1 ]] && APPLY_ALL=1

IS_ROOT=0
[[ $EUID -eq 0 ]] && IS_ROOT=1
if [[ $IS_ROOT -ne 1 ]]; then
    echo "ADVERTENCIA: no se esta ejecutando como root. La auditoria puede mostrar 'Error' en varios controles y la remediacion fallara." >&2
fi

OS_ID="desconocido"
OS_VERSION="desconocida"
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-desconocido}"
    OS_VERSION="${VERSION_ID:-desconocida}"
fi
if [[ "$OS_ID" != "rhel" ]]; then
    echo "ADVERTENCIA: este script fue disenado para Red Hat Enterprise Linux (detectado: ID=$OS_ID VERSION_ID=$OS_VERSION). Algunos controles pueden no aplicar o dar resultados inexactos en otras distribuciones." >&2
fi

# ---------------------------------------------------------------------------
# Utilidades genericas
# ---------------------------------------------------------------------------

_perm_le() { # $1=modo_actual(3 digitos) $2=modo_maximo(3 digitos) -> compara digito a digito
    local i a m
    for i in 0 1 2; do
        a=${1:$i:1}
        m=${2:$i:1}
        (( a > m )) && return 1
    done
    return 0
}

_test_service_active_enabled() { # $1=servicio -> imprime "enabled/active" etc.
    local enabled active
    enabled=$(systemctl is-enabled "$1" 2>/dev/null || echo "unknown")
    active=$(systemctl is-active "$1" 2>/dev/null || echo "unknown")
    echo "$enabled/$active"
}

# --- sysctl ---
SYSCTL_PERSIST_FILE=/etc/sysctl.d/99-cis-hardening.conf

_set_sysctl() { # $1=parametro $2=valor
    sysctl -w "$1=$2" >/dev/null 2>&1
    if [[ -f "$SYSCTL_PERSIST_FILE" ]] && grep -qE "^\s*${1}\s*=" "$SYSCTL_PERSIST_FILE" 2>/dev/null; then
        sed -i -E "s|^\s*${1}\s*=.*|${1} = ${2}|" "$SYSCTL_PERSIST_FILE"
    else
        echo "${1} = ${2}" >> "$SYSCTL_PERSIST_FILE"
    fi
}

_test_sysctl_eq_multi() { # $1=valor_esperado, resto=parametros
    local expected="$1"; shift
    local p a all_ok=1
    local actuals=()
    for p in "$@"; do
        if ! a=$(sysctl -n "$p" 2>/dev/null); then
            printf 'ERROR\tsysctl %s no disponible\n' "$p"
            return
        fi
        actuals+=("$p=$a")
        [[ "$a" != "$expected" ]] && all_ok=0
    done
    local joined
    joined=$(IFS=', '; echo "${actuals[*]}")
    if [[ $all_ok -eq 1 ]]; then printf 'PASS\t%s\n' "$joined"; else printf 'FAIL\t%s\n' "$joined"; fi
}

_set_sysctl_multi() { # $1=valor, resto=parametros
    local value="$1"; shift
    local p
    for p in "$@"; do _set_sysctl "$p" "$value"; done
}

# --- sshd_config ---
SSHD_CONFIG=/etc/ssh/sshd_config
SSHD_RELOAD_NEEDED=0

_get_sshd_option() { # $1=Directiva
    local key val
    key=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    if [[ $IS_ROOT -eq 1 ]] && command -v sshd >/dev/null 2>&1; then
        val=$(sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==k {$1=""; sub(/^ /,""); print; exit}')
    fi
    if [[ -z "${val:-}" ]]; then
        val=$(grep -iE "^\s*$1\s+" "$SSHD_CONFIG" 2>/dev/null | tail -n1 | awk '{ $1=""; sub(/^ /,""); print }')
    fi
    printf '%s' "${val:-}"
}

_set_sshd_option() { # $1=Directiva $2=Valor
    if grep -qiE "^\s*$1\s+" "$SSHD_CONFIG" 2>/dev/null; then
        sed -i -E "s|^\s*$1\s+.*|$1 $2|I" "$SSHD_CONFIG"
    else
        printf '%s %s\n' "$1" "$2" >> "$SSHD_CONFIG"
    fi
    SSHD_RELOAD_NEEDED=1
}

_reload_sshd_if_needed() {
    if [[ $SSHD_RELOAD_NEEDED -eq 1 ]]; then
        if command -v sshd >/dev/null 2>&1 && sshd -t 2>/dev/null; then
            systemctl reload sshd >/dev/null 2>&1 || systemctl reload ssh >/dev/null 2>&1 || true
        fi
        SSHD_RELOAD_NEEDED=0
    fi
}

# --- login.defs ---
LOGIN_DEFS=/etc/login.defs

_get_login_defs() { # $1=CLAVE
    awk -v k="$1" '$1==k {print $2; exit}' "$LOGIN_DEFS" 2>/dev/null
}

_set_login_defs() { # $1=CLAVE $2=VALOR
    if grep -qE "^\s*$1\s+" "$LOGIN_DEFS" 2>/dev/null; then
        sed -i -E "s|^\s*$1\s+.*|$1   $2|" "$LOGIN_DEFS"
    else
        printf '%s   %s\n' "$1" "$2" >> "$LOGIN_DEFS"
    fi
}

# --- pwquality.conf ---
PWQUALITY_CONF=/etc/security/pwquality.conf

_get_pwquality() { # $1=CLAVE
    awk -F= -v k="$1" '$1 ~ "^[[:space:]]*"k"[[:space:]]*$" {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$PWQUALITY_CONF" 2>/dev/null
}

_set_pwquality() { # $1=CLAVE $2=VALOR
    if [[ -f "$PWQUALITY_CONF" ]] && grep -qE "^\s*$1\s*=" "$PWQUALITY_CONF" 2>/dev/null; then
        sed -i -E "s|^\s*$1\s*=.*|$1 = $2|" "$PWQUALITY_CONF"
    else
        printf '%s = %s\n' "$1" "$2" >> "$PWQUALITY_CONF"
    fi
}

# --- kernel modules ---
MODPROBE_PERSIST_FILE=/etc/modprobe.d/99-cis-hardening.conf

_test_module_disabled() { # $1=modulo
    if lsmod 2>/dev/null | grep -q "^$1\b"; then
        printf 'FAIL\tmodulo cargado actualmente\n'
        return
    fi
    if modprobe -n -v "$1" 2>/dev/null | grep -Eq '^install /bin/(true|false)'; then
        printf 'PASS\tbloqueado y no cargado\n'
        return
    fi
    printf 'FAIL\tno bloqueado explicitamente (podria cargarse)\n'
}

_remediate_module_disable() { # $1=modulo
    if ! grep -q "install $1 /bin/false" "$MODPROBE_PERSIST_FILE" 2>/dev/null; then
        {
            echo "install $1 /bin/false"
            echo "blacklist $1"
        } >> "$MODPROBE_PERSIST_FILE"
    fi
    modprobe -r "$1" >/dev/null 2>&1 || true
}

# --- servicios innecesarios ---
_test_service_absent_or_disabled() { # $1=servicio
    if ! systemctl list-unit-files 2>/dev/null | grep -q "^$1\.service"; then
        printf 'PASS\tno instalado\n'
        return
    fi
    local s
    s=$(_test_service_active_enabled "$1")
    if [[ "$s" == "disabled/inactive" || "$s" == "unknown/inactive" || "$s" == "static/inactive" ]]; then
        printf 'PASS\t%s\n' "$s"
    else
        printf 'FAIL\t%s\n' "$s"
    fi
}

_remediate_disable_service() { # $1=servicio
    systemctl disable --now "$1" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Registro de controles
# ---------------------------------------------------------------------------
CTRL_ID=()
CTRL_CATEGORY=()
CTRL_TITLE=()
CTRL_REF=()
CTRL_TESTFN=()
CTRL_REMFN=()
CTRL_REBOOT=()

add_control() { # id categoria titulo referencia test_fn remediate_fn requiere_reboot(0/1)
    CTRL_ID+=("$1")
    CTRL_CATEGORY+=("$2")
    CTRL_TITLE+=("$3")
    CTRL_REF+=("$4")
    CTRL_TESTFN+=("$5")
    CTRL_REMFN+=("$6")
    CTRL_REBOOT+=("$7")
}

# ---------------- Filesystem: modulos de kernel innecesarios ----------------
test_fs01() { _test_module_disabled cramfs; }
remediate_fs01() { _remediate_module_disable cramfs; }
add_control FS-01 "Filesystem" "Modulo de kernel cramfs deshabilitado" "~CIS 1.1.1.1" test_fs01 remediate_fs01 0

test_fs02() { _test_module_disabled freevxfs; }
remediate_fs02() { _remediate_module_disable freevxfs; }
add_control FS-02 "Filesystem" "Modulo de kernel freevxfs deshabilitado" "~CIS 1.1.1.2" test_fs02 remediate_fs02 0

# ---------------- Network (sysctl) ----------------
test_net01() { _test_sysctl_eq_multi 0 net.ipv4.ip_forward net.ipv6.conf.all.forwarding; }
remediate_net01() { _set_sysctl_multi 0 net.ipv4.ip_forward net.ipv6.conf.all.forwarding; }
add_control NET-01 "Network" "Reenvio de paquetes IP (forwarding) deshabilitado" "~CIS 3.2.1" test_net01 remediate_net01 0

test_net02() { _test_sysctl_eq_multi 0 net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route; }
remediate_net02() { _set_sysctl_multi 0 net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route; }
add_control NET-02 "Network" "Rechazar paquetes con ruta de origen (source routed)" "~CIS 3.3.1" test_net02 remediate_net02 0

test_net03() { _test_sysctl_eq_multi 0 net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects; }
remediate_net03() { _set_sysctl_multi 0 net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects; }
add_control NET-03 "Network" "Ignorar redirecciones ICMP entrantes" "~CIS 3.3.2" test_net03 remediate_net03 0

test_net04() { _test_sysctl_eq_multi 0 net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects; }
remediate_net04() { _set_sysctl_multi 0 net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects; }
add_control NET-04 "Network" "No enviar redirecciones ICMP" "~CIS 3.3.3" test_net04 remediate_net04 0

test_net05() { _test_sysctl_eq_multi 1 net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians; }
remediate_net05() { _set_sysctl_multi 1 net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians; }
add_control NET-05 "Network" "Registrar paquetes 'martian' (log_martians)" "~CIS 3.3.9" test_net05 remediate_net05 0

test_net06() { _test_sysctl_eq_multi 1 net.ipv4.icmp_echo_ignore_broadcasts; }
remediate_net06() { _set_sysctl_multi 1 net.ipv4.icmp_echo_ignore_broadcasts; }
add_control NET-06 "Network" "Ignorar solicitudes ICMP a direcciones broadcast" "~CIS 3.3.6" test_net06 remediate_net06 0

test_net07() { _test_sysctl_eq_multi 1 net.ipv4.tcp_syncookies; }
remediate_net07() { _set_sysctl_multi 1 net.ipv4.tcp_syncookies; }
add_control NET-07 "Network" "TCP SYN cookies habilitado" "~CIS 3.3.8" test_net07 remediate_net07 0

test_net08() { _test_sysctl_eq_multi 0 net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra; }
remediate_net08() { _set_sysctl_multi 0 net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra; }
add_control NET-08 "Network" "No aceptar router advertisements IPv6" "~CIS 3.3.4" test_net08 remediate_net08 0

# ---------------- SSH ----------------
test_ssh01() {
    local v; v=$(_get_sshd_option PermitRootLogin)
    [[ -z "$v" ]] && { printf 'ERROR\tno se pudo determinar (revisa permisos)\n'; return; }
    [[ "$v" == "no" ]] && printf 'PASS\t%s\n' "$v" || printf 'FAIL\t%s\n' "$v"
}
remediate_ssh01() { _set_sshd_option PermitRootLogin no; _reload_sshd_if_needed; }
add_control SSH-01 "SSH" "PermitRootLogin deshabilitado" "~CIS 5.1.7" test_ssh01 remediate_ssh01 0

test_ssh02() {
    local v; v=$(_get_sshd_option PermitEmptyPasswords)
    [[ -z "$v" ]] && { printf 'ERROR\tno se pudo determinar (revisa permisos)\n'; return; }
    [[ "$v" == "no" ]] && printf 'PASS\t%s\n' "$v" || printf 'FAIL\t%s\n' "$v"
}
remediate_ssh02() { _set_sshd_option PermitEmptyPasswords no; _reload_sshd_if_needed; }
add_control SSH-02 "SSH" "Autenticacion con contrasena vacia deshabilitada" "~CIS 5.1.8" test_ssh02 remediate_ssh02 0

test_ssh03() {
    local v; v=$(_get_sshd_option X11Forwarding)
    [[ -z "$v" ]] && { printf 'ERROR\tno se pudo determinar (revisa permisos)\n'; return; }
    [[ "$v" == "no" ]] && printf 'PASS\t%s\n' "$v" || printf 'FAIL\t%s\n' "$v"
}
remediate_ssh03() { _set_sshd_option X11Forwarding no; _reload_sshd_if_needed; }
add_control SSH-03 "SSH" "X11Forwarding deshabilitado" "~CIS 5.1.11" test_ssh03 remediate_ssh03 0

test_ssh04() {
    local v; v=$(_get_sshd_option MaxAuthTries)
    [[ -z "$v" ]] && { printf 'ERROR\tno se pudo determinar (revisa permisos)\n'; return; }
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 && v <= 4 )); then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "$v"; fi
}
remediate_ssh04() { _set_sshd_option MaxAuthTries 4; _reload_sshd_if_needed; }
add_control SSH-04 "SSH" "MaxAuthTries menor o igual a 4" "~CIS 5.1.5" test_ssh04 remediate_ssh04 0

test_ssh05() {
    local v; v=$(_get_sshd_option ClientAliveInterval)
    [[ -z "$v" ]] && { printf 'ERROR\tno se pudo determinar (revisa permisos)\n'; return; }
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 && v <= 300 )); then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "$v"; fi
}
remediate_ssh05() { _set_sshd_option ClientAliveInterval 300; _set_sshd_option ClientAliveCountMax 3; _reload_sshd_if_needed; }
add_control SSH-05 "SSH" "ClientAliveInterval configurado (1-300s)" "~CIS 5.1.19" test_ssh05 remediate_ssh05 0

test_ssh06() {
    local v; v=$(_get_sshd_option Banner)
    [[ -z "$v" ]] && { printf 'ERROR\tno se pudo determinar (revisa permisos)\n'; return; }
    if [[ "$v" != "none" && -f "$v" ]]; then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "$v"; fi
}
remediate_ssh06() {
    [[ -f /etc/issue.net ]] || echo "Acceso autorizado unicamente. Toda actividad puede ser monitoreada." > /etc/issue.net
    _set_sshd_option Banner /etc/issue.net
    _reload_sshd_if_needed
}
add_control SSH-06 "SSH" "Banner de aviso legal configurado" "~CIS 5.1.20" test_ssh06 remediate_ssh06 0

test_ssh07() {
    local v; v=$(_get_sshd_option LoginGraceTime)
    [[ -z "$v" ]] && { printf 'ERROR\tno se pudo determinar (revisa permisos)\n'; return; }
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 && v <= 60 )); then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "$v"; fi
}
remediate_ssh07() { _set_sshd_option LoginGraceTime 60; _reload_sshd_if_needed; }
add_control SSH-07 "SSH" "LoginGraceTime menor o igual a 60s" "~CIS 5.1.21" test_ssh07 remediate_ssh07 0

# ---------------- Password Policy ----------------
test_pwd01() {
    local v; v=$(_get_login_defs PASS_MAX_DAYS)
    [[ -z "$v" ]] && { printf 'ERROR\tPASS_MAX_DAYS no definido\n'; return; }
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 && v <= 365 )); then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "$v"; fi
}
remediate_pwd01() { _set_login_defs PASS_MAX_DAYS 365; }
add_control PWD-01 "Password Policy" "Vigencia maxima de contrasena <= 365 dias" "~CIS 5.4.1.1" test_pwd01 remediate_pwd01 0

test_pwd02() {
    local v; v=$(_get_login_defs PASS_MIN_DAYS)
    [[ -z "$v" ]] && { printf 'ERROR\tPASS_MIN_DAYS no definido\n'; return; }
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 )); then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "$v"; fi
}
remediate_pwd02() { _set_login_defs PASS_MIN_DAYS 1; }
add_control PWD-02 "Password Policy" "Vigencia minima de contrasena >= 1 dia" "~CIS 5.4.1.2" test_pwd02 remediate_pwd02 0

test_pwd03() {
    local v; v=$(_get_login_defs PASS_WARN_AGE)
    [[ -z "$v" ]] && { printf 'ERROR\tPASS_WARN_AGE no definido\n'; return; }
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 7 )); then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "$v"; fi
}
remediate_pwd03() { _set_login_defs PASS_WARN_AGE 7; }
add_control PWD-03 "Password Policy" "Advertencia de expiracion >= 7 dias" "~CIS 5.4.1.3" test_pwd03 remediate_pwd03 0

test_pwd04() {
    [[ -f "$PWQUALITY_CONF" ]] || { printf 'ERROR\t%s no existe\n' "$PWQUALITY_CONF"; return; }
    local v; v=$(_get_pwquality minlen)
    [[ -z "$v" ]] && { printf 'FAIL\tminlen no definido\n'; return; }
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 14 )); then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "$v"; fi
}
remediate_pwd04() { _set_pwquality minlen 14; }
add_control PWD-04 "Password Policy" "Longitud minima de contrasena (pwquality) >= 14" "~CIS 5.4.2" test_pwd04 remediate_pwd04 0

test_pwd05() {
    [[ -f "$PWQUALITY_CONF" ]] || { printf 'ERROR\t%s no existe\n' "$PWQUALITY_CONF"; return; }
    local v; v=$(_get_pwquality minclass)
    [[ -z "$v" ]] && { printf 'FAIL\tminclass no definido\n'; return; }
    if [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 4 )); then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "$v"; fi
}
remediate_pwd05() { _set_pwquality minclass 4; }
add_control PWD-05 "Password Policy" "Complejidad minima (minclass) >= 4 clases de caracteres" "~CIS 5.4.2" test_pwd05 remediate_pwd05 0

# ---------------- Cuentas / Autenticacion ----------------
test_acc01() {
    local extra
    extra=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null)
    [[ -z "$extra" ]] && printf 'PASS\tsolo root con UID 0\n' || printf 'FAIL\t%s\n' "$extra"
}
add_control ACC-01 "Accounts" "Ninguna cuenta aparte de root tiene UID 0" "~CIS 6.2.9" test_acc01 "" 0

test_acc02() {
    [[ $IS_ROOT -eq 1 ]] || { printf 'ERROR\tse requiere root para leer /etc/shadow\n'; return; }
    local empty
    empty=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
    [[ -z "$empty" ]] && printf 'PASS\tninguna\n' || printf 'FAIL\t%s\n' "$empty"
}
remediate_acc02() {
    local u
    for u in $(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null); do
        passwd -l "$u" >/dev/null 2>&1
    done
}
add_control ACC-02 "Accounts" "Ninguna cuenta con contrasena vacia" "~CIS 6.2.10" test_acc02 remediate_acc02 0

FAILLOCK_CONF=/etc/security/faillock.conf
test_acc03() {
    [[ -f "$FAILLOCK_CONF" ]] || { printf 'FAIL\t%s no existe\n' "$FAILLOCK_CONF"; return; }
    local deny; deny=$(awk -F= '/^\s*deny\s*=/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' "$FAILLOCK_CONF")
    if [[ "$deny" =~ ^[0-9]+$ ]] && (( deny >= 1 && deny <= 5 )); then printf 'PASS\tdeny=%s\n' "$deny"; else printf 'FAIL\tdeny=%s\n' "${deny:-no definido}"; fi
}
remediate_acc03() {
    if [[ -f "$FAILLOCK_CONF" ]]; then
        if grep -qE '^\s*deny\s*=' "$FAILLOCK_CONF"; then
            sed -i -E 's|^\s*deny\s*=.*|deny = 5|' "$FAILLOCK_CONF"
        else
            echo "deny = 5" >> "$FAILLOCK_CONF"
        fi
    fi
    command -v authselect >/dev/null 2>&1 && authselect enable-feature with-faillock >/dev/null 2>&1
    true
}
add_control ACC-03 "Accounts" "Bloqueo de cuenta tras intentos fallidos (pam_faillock, deny 1-5)" "~CIS 5.5.2" test_acc03 remediate_acc03 0

test_acc04() {
    local v; v=$(_get_login_defs UMASK)
    if [[ "$v" == "027" || "$v" == "077" ]]; then printf 'PASS\t%s\n' "$v"; else printf 'FAIL\t%s\n' "${v:-no definido}"; fi
}
remediate_acc04() { _set_login_defs UMASK 027; }
add_control ACC-04 "Accounts" "UMASK por defecto 027 o mas restrictivo" "~CIS 5.4.3" test_acc04 remediate_acc04 0

# ---------------- Auditoria / Logging ----------------
test_aud01() {
    command -v systemctl >/dev/null 2>&1 || { printf 'ERROR\tsystemctl no disponible\n'; return; }
    local s; s=$(_test_service_active_enabled auditd)
    [[ "$s" == "enabled/active" ]] && printf 'PASS\t%s\n' "$s" || printf 'FAIL\t%s\n' "$s"
}
remediate_aud01() { systemctl enable --now auditd >/dev/null 2>&1; }
add_control AUD-01 "Audit Logging" "Servicio auditd habilitado y activo" "~CIS 6.1.1" test_aud01 remediate_aud01 0

test_aud02() {
    if systemctl list-unit-files 2>/dev/null | grep -q '^rsyslog\.service'; then
        local s; s=$(_test_service_active_enabled rsyslog)
        [[ "$s" == "enabled/active" ]] && printf 'PASS\trsyslog %s\n' "$s" || printf 'FAIL\trsyslog %s\n' "$s"
    else
        local storage; storage=$(awk -F= '/^\s*Storage\s*=/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/systemd/journald.conf 2>/dev/null)
        [[ "$storage" == "persistent" ]] && printf 'PASS\tjournald Storage=%s\n' "$storage" || printf 'FAIL\tjournald Storage=%s\n' "${storage:-auto}"
    fi
}
remediate_aud02() {
    if systemctl list-unit-files 2>/dev/null | grep -q '^rsyslog\.service'; then
        systemctl enable --now rsyslog >/dev/null 2>&1
    else
        mkdir -p /var/log/journal
        if grep -qE '^\s*#?\s*Storage\s*=' /etc/systemd/journald.conf 2>/dev/null; then
            sed -i -E 's|^\s*#?\s*Storage\s*=.*|Storage=persistent|' /etc/systemd/journald.conf
        else
            echo "Storage=persistent" >> /etc/systemd/journald.conf
        fi
        systemctl restart systemd-journald >/dev/null 2>&1
    fi
}
add_control AUD-02 "Audit Logging" "Logging centralizado/persistente habilitado (rsyslog o journald)" "~CIS 6.1.2" test_aud02 remediate_aud02 0

# ---------------- SELinux ----------------
test_sel01() {
    command -v getenforce >/dev/null 2>&1 || { printf 'ERROR\tgetenforce no disponible\n'; return; }
    local v; v=$(getenforce)
    [[ "$v" == "Enforcing" ]] && printf 'PASS\t%s\n' "$v" || printf 'FAIL\t%s\n' "$v"
}
remediate_sel01() {
    setenforce 1 >/dev/null 2>&1 || true
    [[ -f /etc/selinux/config ]] && sed -i -E 's|^SELINUX=.*|SELINUX=enforcing|' /etc/selinux/config
}
add_control SEL-01 "SELinux" "SELinux en modo Enforcing" "~CIS 1.2.1" test_sel01 remediate_sel01 1

# ---------------- Firewall ----------------
test_fw01() {
    command -v systemctl >/dev/null 2>&1 || { printf 'ERROR\tsystemctl no disponible\n'; return; }
    local s; s=$(_test_service_active_enabled firewalld)
    [[ "$s" == "enabled/active" ]] && printf 'PASS\t%s\n' "$s" || printf 'FAIL\t%s\n' "$s"
}
remediate_fw01() { systemctl enable --now firewalld >/dev/null 2>&1; }
add_control FW-01 "Firewall" "firewalld habilitado y activo" "~CIS 4.2.1" test_fw01 remediate_fw01 0

# ---------------- Sincronizacion de tiempo ----------------
test_time01() {
    command -v systemctl >/dev/null 2>&1 || { printf 'ERROR\tsystemctl no disponible\n'; return; }
    local s; s=$(_test_service_active_enabled chronyd)
    [[ "$s" == "enabled/active" ]] && printf 'PASS\t%s\n' "$s" || printf 'FAIL\t%s\n' "$s"
}
remediate_time01() { systemctl enable --now chronyd >/dev/null 2>&1; }
add_control TIME-01 "Time Sync" "chronyd habilitado y activo" "~CIS 2.1.1" test_time01 remediate_time01 0

# ---------------- Permisos de archivos criticos ----------------
test_perm01() {
    local f=/etc/passwd
    [[ -e "$f" ]] || { printf 'ERROR\t%s no existe\n' "$f"; return; }
    local mode owner group ok=1
    mode=$(printf '%03d' "$((10#$(stat -c '%a' "$f" 2>/dev/null)))")
    owner=$(stat -c '%U' "$f"); group=$(stat -c '%G' "$f")
    _perm_le "$mode" "644" || ok=0
    [[ "$owner" != "root" ]] && ok=0
    [[ "$group" != "root" ]] && ok=0
    [[ $ok -eq 1 ]] && printf 'PASS\t%s %s:%s\n' "$mode" "$owner" "$group" || printf 'FAIL\t%s %s:%s\n' "$mode" "$owner" "$group"
}
remediate_perm01() { chmod u-s,g-s,644 /etc/passwd; chown root:root /etc/passwd; }
add_control PERM-01 "File Permissions" "/etc/passwd con permisos 644 o mas restrictivo, root:root" "~CIS 6.1.2" test_perm01 remediate_perm01 0

test_perm02() {
    local f=/etc/shadow
    [[ -e "$f" ]] || { printf 'ERROR\t%s no existe\n' "$f"; return; }
    local mode owner group ok=1
    mode=$(printf '%03d' "$((10#$(stat -c '%a' "$f" 2>/dev/null)))")
    owner=$(stat -c '%U' "$f"); group=$(stat -c '%G' "$f")
    _perm_le "$mode" "000" || ok=0
    [[ "$owner" != "root" ]] && ok=0
    [[ "$group" != "root" && "$group" != "shadow" ]] && ok=0
    [[ $ok -eq 1 ]] && printf 'PASS\t%s %s:%s\n' "$mode" "$owner" "$group" || printf 'FAIL\t%s %s:%s\n' "$mode" "$owner" "$group"
}
remediate_perm02() { chmod 000 /etc/shadow; chown root:root /etc/shadow; }
add_control PERM-02 "File Permissions" "/etc/shadow sin permisos de lectura/escritura directos (0000), root:root" "~CIS 6.1.3" test_perm02 remediate_perm02 0

test_perm03() {
    local f=/etc/gshadow
    [[ -e "$f" ]] || { printf 'ERROR\t%s no existe\n' "$f"; return; }
    local mode owner group ok=1
    mode=$(printf '%03d' "$((10#$(stat -c '%a' "$f" 2>/dev/null)))")
    owner=$(stat -c '%U' "$f"); group=$(stat -c '%G' "$f")
    _perm_le "$mode" "000" || ok=0
    [[ "$owner" != "root" ]] && ok=0
    [[ "$group" != "root" && "$group" != "shadow" ]] && ok=0
    [[ $ok -eq 1 ]] && printf 'PASS\t%s %s:%s\n' "$mode" "$owner" "$group" || printf 'FAIL\t%s %s:%s\n' "$mode" "$owner" "$group"
}
remediate_perm03() { chmod 000 /etc/gshadow; chown root:root /etc/gshadow; }
add_control PERM-03 "File Permissions" "/etc/gshadow sin permisos de lectura/escritura directos (0000), root:root" "~CIS 6.1.5" test_perm03 remediate_perm03 0

# ---------------- Servicios innecesarios ----------------
test_svc01() { _test_service_absent_or_disabled avahi-daemon; }
remediate_svc01() { _remediate_disable_service avahi-daemon; }
add_control SVC-01 "Services" "Servicio avahi-daemon no instalado o deshabilitado" "~CIS 2.2.1" test_svc01 remediate_svc01 0

test_svc02() { _test_service_absent_or_disabled cups; }
remediate_svc02() { _remediate_disable_service cups; }
add_control SVC-02 "Services" "Servicio cups no instalado o deshabilitado (no aplica a servidores de impresion)" "~CIS 2.2.4" test_svc02 remediate_svc02 0

# ---------------------------------------------------------------------------
# Ejecucion
# ---------------------------------------------------------------------------

csv_field() { local s="${1//\"/\"\"}"; printf '"%s"' "$s"; }
json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

RESULTS_ID=(); RESULTS_CATEGORY=(); RESULTS_TITLE=(); RESULTS_REF=()
RESULTS_STATUS=(); RESULTS_ACTUAL=(); RESULTS_REMEDIATED=(); RESULTS_REBOOT=(); RESULTS_ERROR=()

confirm_remediation() { # $1=id $2=titulo -> return 0=si 1=no
    [[ $APPLY_ALL -eq 1 ]] && return 0
    [[ $SKIP_ALL -eq 1 ]] && return 1
    local resp
    while true; do
        read -r -p "  Remediar [$1] '$2'? (Y=si / N=no / A=todos / S=omitir todos / Q=salir): " resp
        case "${resp^^}" in
            Y) return 0 ;;
            N) return 1 ;;
            A) APPLY_ALL=1; return 0 ;;
            S) SKIP_ALL=1; return 1 ;;
            Q) echo; echo "Interrumpido por el usuario."; write_results; exit 0 ;;
            *) echo "  Responde Y, N, A, S o Q." ;;
        esac
    done
}

write_results() {
    if [[ -z "$OUTPUT_PATH" ]]; then
        OUTPUT_PATH="${SCRIPT_DIR}/CIS-RHEL-Report_$(date +%Y%m%d_%H%M%S)"
    fi
    mkdir -p "$OUTPUT_PATH"

    local csv_path="${OUTPUT_PATH}/CIS-RHEL-Results.csv"
    local json_path="${OUTPUT_PATH}/CIS-RHEL-Results.json"

    {
        echo '"Id","Category","Title","Reference","Status","Actual","RemediationApplied","RequiresReboot","Error"'
        local i
        for i in "${!RESULTS_ID[@]}"; do
            printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
                "$(csv_field "${RESULTS_ID[$i]}")" \
                "$(csv_field "${RESULTS_CATEGORY[$i]}")" \
                "$(csv_field "${RESULTS_TITLE[$i]}")" \
                "$(csv_field "${RESULTS_REF[$i]}")" \
                "$(csv_field "${RESULTS_STATUS[$i]}")" \
                "$(csv_field "${RESULTS_ACTUAL[$i]}")" \
                "$(csv_field "${RESULTS_REMEDIATED[$i]}")" \
                "$(csv_field "${RESULTS_REBOOT[$i]}")" \
                "$(csv_field "${RESULTS_ERROR[$i]}")"
        done
    } > "$csv_path"

    {
        echo '['
        local i last=$(( ${#RESULTS_ID[@]} - 1 ))
        for i in "${!RESULTS_ID[@]}"; do
            printf '  {"Id":"%s","Category":"%s","Title":"%s","Reference":"%s","Status":"%s","Actual":"%s","RemediationApplied":"%s","RequiresReboot":"%s","Error":"%s"}%s\n' \
                "$(json_escape "${RESULTS_ID[$i]}")" \
                "$(json_escape "${RESULTS_CATEGORY[$i]}")" \
                "$(json_escape "${RESULTS_TITLE[$i]}")" \
                "$(json_escape "${RESULTS_REF[$i]}")" \
                "$(json_escape "${RESULTS_STATUS[$i]}")" \
                "$(json_escape "${RESULTS_ACTUAL[$i]}")" \
                "$(json_escape "${RESULTS_REMEDIATED[$i]}")" \
                "$(json_escape "${RESULTS_REBOOT[$i]}")" \
                "$(json_escape "${RESULTS_ERROR[$i]}")" \
                "$([[ $i -lt $last ]] && echo ',')"
        done
        echo ']'
    } > "$json_path"

    echo
    echo "Reportes generados:"
    echo "  CSV : $csv_path"
    echo "  JSON: $json_path"
}

echo "=== Auditoria CIS-aligned RHEL (Nivel 1) ==="
echo "Sistema detectado: ID=$OS_ID VERSION_ID=$OS_VERSION"
echo "Modo remediacion: $([[ $REMEDIATE -eq 1 ]] && echo ACTIVADO || echo 'desactivado (solo auditoria)')"
echo

for i in "${!CTRL_ID[@]}"; do
    id="${CTRL_ID[$i]}"; category="${CTRL_CATEGORY[$i]}"; title="${CTRL_TITLE[$i]}"
    ref="${CTRL_REF[$i]}"; testfn="${CTRL_TESTFN[$i]}"; remfn="${CTRL_REMFN[$i]}"; reboot="${CTRL_REBOOT[$i]}"

    printf '[%-8s] %-70s' "$id" "$title"

    output=$("$testfn" 2>&1)
    last_line=$(printf '%s\n' "$output" | tail -n1)
    status="${last_line%%$'\t'*}"
    actual="${last_line#*$'\t'}"
    [[ "$status" == "$last_line" ]] && actual=""
    error_msg=""
    remediated="false"

    case "$status" in
        PASS) echo " [OK]" ;;
        FAIL) echo " [FAIL]" ;;
        ERROR) echo " [ERROR]"; error_msg="$actual" ;;
        *) echo " [DESCONOCIDO]"; status="Unknown" ;;
    esac

    if [[ "$status" == "FAIL" && $REMEDIATE -eq 1 && -n "$remfn" ]]; then
        if [[ $IS_ROOT -ne 1 ]]; then
            echo "    -> Se omite remediacion: se requiere root."
        elif confirm_remediation "$id" "$title"; then
            if "$remfn" 2>/tmp/cis_rem_err_$$; then
                remediated="true"
                echo "    -> Remediado."
                newoutput=$("$testfn" 2>&1)
                actual="${newoutput#*$'\t'}"
            else
                error_msg="Error al remediar: $(cat /tmp/cis_rem_err_$$ 2>/dev/null)"
                echo "    -> $error_msg"
            fi
            rm -f /tmp/cis_rem_err_$$
        fi
    elif [[ "$status" == "FAIL" && $REMEDIATE -eq 1 && -z "$remfn" ]]; then
        echo "    -> Sin remediacion automatica (requiere revision manual)."
    fi

    RESULTS_ID+=("$id"); RESULTS_CATEGORY+=("$category"); RESULTS_TITLE+=("$title"); RESULTS_REF+=("$ref")
    RESULTS_STATUS+=("$status"); RESULTS_ACTUAL+=("$actual"); RESULTS_REMEDIATED+=("$remediated")
    RESULTS_REBOOT+=("$([[ "$reboot" == "1" ]] && echo true || echo false)"); RESULTS_ERROR+=("$error_msg")
done

pass=0; fail=0; err=0; unk=0
for s in "${RESULTS_STATUS[@]}"; do
    case "$s" in
        PASS) ((pass++)) ;;
        FAIL) ((fail++)) ;;
        ERROR) ((err++)) ;;
        *) ((unk++)) ;;
    esac
done
total=${#RESULTS_STATUS[@]}
pct=0
[[ $total -gt 0 ]] && pct=$(awk -v p="$pass" -v t="$total" 'BEGIN{printf "%.1f", (p/t)*100}')

echo
echo "=== Resumen ==="
echo "Total: $total | Cumple: $pass | No cumple: $fail | Error: $err | Desconocido: $unk"
echo "Cumplimiento: ${pct}%"

needs_reboot=0
for i in "${!RESULTS_REMEDIATED[@]}"; do
    if [[ "${RESULTS_REMEDIATED[$i]}" == "true" && "${RESULTS_REBOOT[$i]}" == "true" ]]; then
        needs_reboot=1
        break
    fi
done
[[ $needs_reboot -eq 1 ]] && echo && echo "Algunos controles remediados requieren REINICIAR el equipo para tener efecto completo."

write_results
