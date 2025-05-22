# Documentación Técnica - Sistema de Criptografía y Seguridad Digital

## Arquitectura del Sistema

### Estructura General
```
SecCriptoFinalProyect/
├── src/          # Núcleo criptográfico
├── web/         # Interfaz web
├── tests/       # Pruebas unitarias
└── docs/        # Documentación
```

### Componentes Principales

1. **Núcleo Criptográfico** (`src/`)
   - Implementación de algoritmos criptográficos
   - Gestión de claves
   - Operaciones de hash

2. **Interfaz Web** (`web/`)
   - Servidor Flask
   - Plantillas HTML
   - Gestión de archivos

3. **Sistema de Pruebas** (`tests/`)
   - Pruebas unitarias
   - Pruebas de integración

## Tecnologías Utilizadas

### Backend
- **Python 3.8+**: Lenguaje principal de desarrollo
- **Flask**: Framework web
- **Cryptography**: Biblioteca para operaciones criptográficas
- **Bootstrap 5**: Framework CSS para la interfaz

### Bibliotecas Principales
```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
```

## Implementación de Funcionalidades

### 1. Cifrado Simétrico (AES)

#### Generación de Claves
```python
def generar_clave(bits=256):
    return os.urandom(bits // 8)
```

#### Cifrado/Descifrado
- Utiliza AES en modo CBC
- Padding PKCS7
- IV aleatorio generado para cada operación

### 2. Cifrado Asimétrico (RSA)

#### Generación de Claves
```python
def generar_claves_rsa():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()
```

#### Cifrado/Descifrado
- Padding OAEP con SHA-256
- MGF1 como función de máscara

### 3. Firma Digital

#### Firma
- RSA con PSS padding
- SHA-256 para el hash del mensaje
- Verificación de integridad y autenticidad

### 4. Hash Criptográfico

#### Cálculo de Hash
- Algoritmo SHA-256
- Procesamiento por bloques para archivos grandes
- Verificación de integridad

## Seguridad

### Medidas Implementadas

1. **Gestión de Memoria**
   - Operaciones criptográficas en memoria
   - Limpieza inmediata de datos sensibles
   - No persistencia de claves en disco

2. **Manejo de Archivos**
   - Validación de tipos de archivo
   - Nombres de archivo seguros
   - Limpieza automática de archivos temporales

3. **Protección Web**
   - CSRF tokens
   - Headers de seguridad
   - Validación de entradas

### Consideraciones de Seguridad

1. **Claves**
   - RSA: 2048 bits mínimo
   - AES: 128/192/256 bits
   - Generación segura de números aleatorios

2. **Almacenamiento**
   - No se almacenan claves en el servidor
   - Archivos temporales con permisos restrictivos
   - Limpieza periódica de archivos

## API y Endpoints

### Rutas Principales

```python
@app.route('/')
def index():
    # Página principal

@app.route('/aes', methods=['GET', 'POST'])
def aes():
    # Operaciones AES

@app.route('/rsa', methods=['GET', 'POST'])
def rsa():
    # Operaciones RSA

@app.route('/firma', methods=['GET', 'POST'])
def firma():
    # Operaciones de firma digital

@app.route('/hash', methods=['GET', 'POST'])
def hash():
    # Operaciones de hash
```

### Manejo de Archivos

```python
def guardar_archivo_temporal(archivo):
    """Guarda un archivo temporalmente y retorna su ruta"""
    filename = secure_filename(archivo.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    archivo.save(filepath)
    return filepath
```

## Pruebas

### Pruebas Unitarias

```python
def test_generar_clave_aes():
    """Prueba la generación de claves AES"""
    clave = generar_clave(256)
    assert len(clave) == 32

def test_cifrado_descifrado_aes():
    """Prueba el ciclo completo de cifrado/descifrado AES"""
    texto = b"Texto de prueba"
    clave = generar_clave()
    cifrado = cifrar_archivo(texto, clave)
    descifrado = descifrar_archivo(cifrado, clave)
    assert texto == descifrado
```

### Cobertura de Pruebas
- Pruebas unitarias para cada módulo
- Pruebas de integración para flujos completos
- Pruebas de seguridad y casos límite

## Mantenimiento y Desarrollo

### Guías de Desarrollo
1. Seguir PEP 8 para estilo de código Python
2. Documentar todas las funciones y clases
3. Mantener pruebas actualizadas
4. Revisión de seguridad en cada cambio

### Proceso de Despliegue
1. Ejecutar pruebas unitarias
2. Verificar dependencias
3. Actualizar documentación
4. Revisión de seguridad
5. Despliegue en producción

## Rendimiento y Optimización

### Consideraciones
- Procesamiento en memoria para archivos pequeños
- Procesamiento por bloques para archivos grandes
- Caché de resultados cuando sea seguro
- Limpieza periódica de recursos

### Monitoreo
- Logs de operaciones críticas
- Métricas de rendimiento
- Alertas de seguridad
- Uso de recursos

## Apéndices

### A. Dependencias
```
Flask==2.0.1
cryptography==3.4.7
Flask-Bootstrap==3.3.7.1
Werkzeug==2.0.1
```

### B. Variables de Configuración
```python
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['SECRET_KEY'] = os.urandom(24)
```

### C. Códigos de Error
- 400: Error en la solicitud
- 401: No autorizado
- 403: Prohibido
- 404: No encontrado
- 500: Error interno del servidor

## Referencias

1. [Documentación de Cryptography](https://cryptography.io/en/latest/)
2. [Flask Documentation](https://flask.palletsprojects.com/)
3. [NIST Cryptographic Standards](https://csrc.nist.gov/publications/fips)
4. [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
