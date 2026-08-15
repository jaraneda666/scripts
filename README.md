# scripts

Colección personal de scripts de automatización y seguridad, organizados por
categoría. Cada script vive en su propia carpeta con su propio `README.md`
detallando requisitos, uso y limitaciones.

## Contenido

| Script | Categoría | Descripción |
|--------|-----------|-------------|
| [CIS-Win11-Audit](windows/cis-win11-audit/) | Windows / Seguridad | Audita (y opcionalmente remedia) configuraciones de endurecimiento de Windows 11 alineadas con controles de Nivel 1 tipo CIS Benchmark. |

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

La mayoría de los scripts de este repositorio están pensados para:

- **Windows** con **PowerShell 5.1+** o **PowerShell 7+**.
- Ejecución en consola **elevada (Administrador)** cuando el script lo
  requiera para leer o modificar configuración del sistema — esto se indica
  en el README de cada script.

Ningún script de este repositorio se ejecuta ni modifica el sistema por sí
solo al clonarlo: siempre requieren invocación manual explícita.

## Uso general

```powershell
git clone https://github.com/jaraneda666/scripts.git
cd scripts\<categoria>\<nombre-script>
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
