# Manual de Usuario - Sistema de Criptografía y Seguridad Digital

Este manual proporciona instrucciones detalladas sobre cómo utilizar cada función del sistema de criptografía.

## Índice

1. [Inicio](#inicio)
2. [Cifrado AES](#cifrado-aes)
3. [Cifrado RSA](#cifrado-rsa)
4. [Firma Digital](#firma-digital)
5. [Hash Criptográfico](#hash-criptográfico)
6. [Solución de Problemas](#solución-de-problemas)

## Inicio

1. Acceda a la aplicación a través de su navegador web en `http://localhost:5000`
2. En la página principal, encontrará cuatro opciones principales:
   - Cifrado AES (Simétrico)
   - Cifrado RSA (Asimétrico)
   - Firma Digital
   - Hash Criptográfico

## Cifrado AES

### Paso 1: Generar Clave AES
1. Seleccione el tamaño de clave deseado (128, 192 o 256 bits)
2. Haga clic en "Generar Clave"
3. Guarde el archivo de clave (.key) en una ubicación segura

### Paso 2: Preparar Texto
1. Ingrese el texto que desea cifrar en el campo de texto
2. O cargue un archivo de texto
3. Haga clic en "Guardar Texto" para descargar el archivo

### Paso 3: Cifrar
1. Seleccione el archivo de texto a cifrar
2. Seleccione el archivo de clave (.key)
3. Haga clic en "Cifrar"
4. Guarde el archivo cifrado (.enc)

### Paso 4: Descifrar
1. Seleccione el archivo cifrado (.enc)
2. Seleccione el archivo de clave (.key)
3. Haga clic en "Descifrar"
4. Guarde el archivo descifrado

## Cifrado RSA

### Paso 1: Generar Par de Claves
1. Haga clic en "Generar Par de Claves RSA"
2. Se descargará un archivo ZIP conteniendo:
   - Clave privada (private.pem)
   - Clave pública (public.pem)
3. Guarde ambas claves de forma segura

### Paso 2: Preparar Texto
1. Ingrese el texto a cifrar
2. O cargue un archivo de texto
3. Haga clic en "Guardar Texto"

### Paso 3: Cifrar
1. Seleccione el archivo a cifrar
2. Seleccione la clave pública (.pem)
3. Haga clic en "Cifrar"
4. Guarde el archivo cifrado

### Paso 4: Descifrar
1. Seleccione el archivo cifrado
2. Seleccione la clave privada (.pem)
3. Haga clic en "Descifrar"
4. Guarde el archivo descifrado

## Firma Digital

### Paso 1: Generar Par de Claves
1. Haga clic en "Generar Par de Claves"
2. Se descargará un archivo ZIP con las claves
3. Guarde ambas claves de forma segura

### Paso 2: Preparar Documento
1. Ingrese el texto a firmar
2. O cargue un archivo
3. Haga clic en "Guardar Texto"

### Paso 3: Firmar
1. Seleccione el archivo a firmar
2. Seleccione la clave privada (.pem)
3. Haga clic en "Firmar"
4. Guarde el archivo de firma (.sig)

### Paso 4: Verificar
1. Seleccione el archivo original
2. Seleccione el archivo de firma (.sig)
3. Seleccione la clave pública (.pem)
4. Haga clic en "Verificar"
5. El sistema mostrará si la firma es válida

## Hash Criptográfico

### Calcular Hash
1. Seleccione el archivo
2. Haga clic en "Calcular Hash"
3. Guarde el archivo de hash (.sha256)

### Verificar Hash
1. Seleccione el archivo original
2. Seleccione el archivo de hash (.sha256)
3. Haga clic en "Verificar"
4. El sistema mostrará si el archivo mantiene su integridad

## Solución de Problemas

### Problemas Comunes

1. **Error al generar clave**
   - Verifique que tiene permisos de escritura en la carpeta de destino
   - Intente generar la clave nuevamente

2. **Error al cifrar/descifrar**
   - Verifique que está usando la clave correcta
   - Asegúrese de que el archivo no está corrupto
   - Para RSA, verifique usar la clave pública para cifrar y la privada para descifrar

3. **Error en firma digital**
   - Verifique usar la clave privada para firmar
   - Verifique usar la clave pública para verificar
   - Asegúrese de que el archivo no ha sido modificado

4. **Error en verificación de hash**
   - Verifique que el archivo no ha sido modificado
   - Asegúrese de usar el archivo de hash correcto

### Recomendaciones de Seguridad

1. **Gestión de Claves**
   - Guarde las claves privadas en un lugar seguro
   - Nunca comparta las claves privadas
   - Haga copias de seguridad de sus claves

2. **Protección de Datos**
   - No deje archivos sensibles sin cifrar
   - Elimine archivos temporales después de usarlos
   - Use contraseñas fuertes para proteger sus claves

3. **Buenas Prácticas**
   - Verifique siempre las firmas digitales
   - Compruebe la integridad de los archivos importantes
   - Mantenga actualizado el software

Para más información o soporte técnico, consulte la documentación técnica o contacte al equipo de desarrollo.
