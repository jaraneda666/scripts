# scripts

Colección personal de scripts de automatización y seguridad, organizados por
categoría. Cada script vive en su propia carpeta con su propio `README.md`
detallando requisitos, uso y limitaciones.

## Contenido

| Script | Categoría | Descripción |
|--------|-----------|-------------|
| [CIS-Win11-Audit](windows/cis-win11-audit/) | Windows / Seguridad | Audita (y opcionalmente remedia) configuraciones de endurecimiento de Windows 11 alineadas con controles de Nivel 1 tipo CIS Benchmark. |
| [CIS-RHEL-Audit](linux/cis-rhel-audit/) | Linux / Seguridad | Equivalente en Bash para Red Hat Enterprise Linux (RHEL 9 / RHEL 10): audita (y opcionalmente remedia) controles de endurecimiento de Nivel 1 tipo CIS Benchmark. |

## Estructura del repositorio

```
scripts/
├── README.md          <- este archivo
├── LICENSE
├── .gitignore
├── .gitattributes
└── <categoria>/
    └── <nombre-script>/
        ├── README.md          <- documentación específica del script
        └── <archivos del script>
```

Cada carpeta de script es autocontenida: incluye su propia documentación de
uso, requisitos y parámetros. Este README raíz solo actúa como índice.

## Requisitos generales

Los scripts de este repositorio están agrupados por plataforma:

- **`windows/`** — PowerShell 5.1+ o PowerShell 7+, ejecutados en consola
  **elevada (Administrador)** cuando el script lo requiera.
- **`linux/`** — Bash 4+, ejecutados con **`sudo`/root** cuando el script lo
  requiera.

Cada README de script indica exactamente qué privilegios necesita y qué
pasa si se ejecuta sin ellos (normalmente: la auditoría muestra `Error` en
los controles afectados y la remediación se omite).

Ningún script de este repositorio se ejecuta ni modifica el sistema por sí
solo al clonarlo: siempre requieren invocación manual explícita.

## Uso general

```bash
git clone https://github.com/jaraneda666/scripts.git
cd scripts/<categoria>/<nombre-script>
# Ver el README.md de esa carpeta para parámetros y ejemplos concretos
```

## Licencia

Este repositorio se distribuye bajo la [licencia MIT](LICENSE), salvo que se
indique lo contrario en la carpeta de un script específico.

## Descargo de responsabilidad

Estos scripts se proveen "tal cual", sin garantía de ningún tipo. Revisa el
código antes de ejecutarlo en sistemas de producción, especialmente aquellos
que modifican configuración de seguridad o del sistema operativo. El autor no
se hace responsable por daños derivados de su uso.
