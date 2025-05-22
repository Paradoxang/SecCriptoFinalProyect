# Sistema de Criptografía y Seguridad Digital

Este proyecto implementa una aplicación web que proporciona herramientas criptográficas para cifrado, firma digital y verificación de integridad de archivos.

## Características

- **Cifrado Simétrico (AES)**
  - Generación de claves AES
  - Cifrado/descifrado de archivos
  - Soporte para diferentes tamaños de clave (128, 192, 256 bits)

- **Cifrado Asimétrico (RSA)**
  - Generación de pares de claves RSA
  - Cifrado/descifrado de archivos
  - Gestión segura de claves públicas y privadas

- **Firma Digital**
  - Generación de pares de claves para firma
  - Firma de documentos
  - Verificación de firmas
  - Validación de autenticidad e integridad

- **Hash Criptográfico**
  - Cálculo de hash SHA-256
  - Verificación de integridad de archivos
  - Detección de modificaciones

## Requisitos del Sistema

- Python 3.8 o superior
- pip (gestor de paquetes de Python)
- Navegador web moderno

## Instalación

1. Clonar el repositorio:
   ```bash
   git clone <url-del-repositorio>
   cd SecCriptoFinalProyect
   ```

2. Crear un entorno virtual (recomendado):
   ```bash
   python -m venv venv
   source venv/bin/activate  # En Linux/Mac
   # o
   venv\Scripts\activate  # En Windows
   ```

3. Instalar dependencias:
   ```bash
   pip install -r requirements.txt
   ```

## Ejecución

### Ejecución (Linux/Mac/Windows)

1. Navegar al directorio del proyecto:
   ```bash
   cd SecCriptoFinalProyect
   ```

2. Ejecutar la aplicación directamente usando el Python del entorno virtual:
   ```bash
   .venv/bin/python web/app.py
   ```

   En Windows, usar la barra invertida:
   ```cmd
   .venv\bin\python web\app.py
   ```

### Acceder a la Aplicación

Una vez que la aplicación esté ejecutándose, abrir el navegador y acceder a:
```
http://localhost:5000
```

### Notas Importantes

- En Linux, si el comando `python` no funciona, usar `python3`
- Asegurarse de que el entorno virtual esté activado (verás `(.venv)` al inicio del prompt)
- Para detener la aplicación, presionar `Ctrl+C` en la terminal
- Si hay problemas con los permisos en Linux, ejecutar:
  ```bash
  chmod +x run.sh
  ```

## Estructura del Proyecto

```
SecCriptoFinalProyect/
├── docs/                    # Documentación detallada
│   ├── manual_usuario.md    # Manual de usuario
│   └── documentacion_tecnica.md  # Documentación técnica
├── src/                     # Código fuente de las funciones criptográficas
│   ├── simetrico.py        # Implementación de cifrado AES
│   ├── asimetrico.py       # Implementación de cifrado RSA
│   ├── firma.py            # Implementación de firma digital
│   └── hash.py             # Implementación de funciones hash
├── web/                     # Aplicación web
│   ├── app.py              # Servidor Flask
│   ├── static/             # Archivos estáticos
│   └── templates/          # Plantillas HTML
├── tests/                   # Pruebas unitarias
├── requirements.txt         # Dependencias del proyecto
└── README.md               # Este archivo
```

## Seguridad

- Las operaciones criptográficas se realizan en memoria para evitar la persistencia de datos sensibles
- Las claves privadas nunca se almacenan en el servidor
- Se utilizan bibliotecas criptográficas probadas y seguras
- Implementación de mejores prácticas de seguridad web

## Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## Contribuir

Las contribuciones son bienvenidas. Por favor, lea `CONTRIBUTING.md` para detalles sobre nuestro código de conducta y el proceso para enviarnos pull requests.
