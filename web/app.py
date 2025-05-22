from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from flask_bootstrap import Bootstrap5
from werkzeug.utils import secure_filename
import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Agregar el directorio src al path para poder importar los módulos
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.simetrico import generar_clave, cifrar_archivo, descifrar_archivo
from src.asimetrico import generar_claves_rsa, cifrar_con_rsa, descifrar_con_rsa
from src.firma import firmar_datos, verificar_firma
from src.hash import calcular_hash_archivo, guardar_hash, verificar_hash_guardado
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
# Configurar la ruta absoluta para los uploads
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
bootstrap = Bootstrap5(app)

def limpiar_archivos_temporales():
    """Limpia todos los archivos del directorio uploads"""
    try:
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                os.unlink(filepath)
            except:
                pass
    except Exception as e:
        print(f'Error al limpiar archivos temporales: {e}')

# Asegurar que existe el directorio de uploads y limpiar archivos temporales
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
limpiar_archivos_temporales()

def guardar_archivo_temporal(archivo):
    """Guarda un archivo subido temporalmente y retorna su ruta"""
    # Asegurarse de que el directorio existe
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Generar un nombre único para el archivo
    import uuid
    filename = f'{uuid.uuid4().hex[:8]}_{secure_filename(archivo.filename)}'
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    archivo.save(filepath)
    return filepath

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/aes', methods=['GET', 'POST'])
def aes():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'generate_key':
            try:
                # Generar clave AES
                bits = int(request.form.get('bits', 256))
                key = generar_clave(bits=bits)
                
                # Crear nombre de archivo con timestamp
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                key_filename = f'aes_{bits}bits_{timestamp}.key'
                
                # Enviar clave como archivo
                from io import BytesIO
                key_file = BytesIO(key)
                flash(f'Clave AES de {bits} bits generada exitosamente', 'success')
                return send_file(
                    key_file,
                    as_attachment=True,
                    download_name=key_filename,
                    mimetype='application/octet-stream'
                )
            except Exception as e:
                flash(f'Error al generar la clave: {str(e)}', 'error')
                return redirect(url_for('aes'))
        
        elif action == 'save_text':
            try:
                # Obtener texto plano
                plaintext = request.form.get('plaintext')
                if not plaintext or not plaintext.strip():
                    flash('El texto no puede estar vacío', 'error')
                    return redirect(url_for('aes'))
                
                # Crear nombre de archivo con timestamp
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                text_filename = f'texto_plano_{timestamp}.txt'
                
                # Enviar texto como archivo
                from io import BytesIO
                text_file = BytesIO(plaintext.encode('utf-8'))
                flash('Texto guardado exitosamente', 'success')
                return send_file(
                    text_file,
                    as_attachment=True,
                    download_name=text_filename,
                    mimetype='text/plain'
                )
            except Exception as e:
                flash(f'Error al guardar el texto: {str(e)}', 'error')
                return redirect(url_for('aes'))
        elif action in ['encrypt', 'decrypt']:
            try:
                # Verificar archivos requeridos
                if 'file' not in request.files or 'key' not in request.files:
                    flash('Se requiere archivo y clave', 'error')
                    return redirect(url_for('aes'))
                
                file = request.files['file']
                key_file = request.files['key']
                
                if file.filename == '' or key_file.filename == '':
                    flash('No se seleccionó archivo', 'error')
                    return redirect(url_for('aes'))
                
                # Leer archivos en memoria
                file_content = file.read()
                key_content = key_file.read()
                
                # Crear archivos temporales en memoria
                from io import BytesIO
                input_buffer = BytesIO(file_content)
                output_buffer = BytesIO()
                
                # Procesar archivo
                if action == 'encrypt':
                    # Cifrar contenido
                    from Crypto.Cipher import AES
                    cipher = AES.new(key_content, AES.MODE_CBC)
                    padded_data = pad(file_content, AES.block_size)
                    ciphertext = cipher.encrypt(padded_data)
                    output_buffer.write(cipher.iv)
                    output_buffer.write(ciphertext)
                    
                    # Generar nombre de archivo
                    import datetime
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    output_filename = f'texto_cifrado_{timestamp}.enc'
                    flash('Archivo cifrado exitosamente', 'success')
                else:
                    # Descifrar contenido
                    from Crypto.Cipher import AES
                    iv = file_content[:16]
                    ciphertext = file_content[16:]
                    cipher = AES.new(key_content, AES.MODE_CBC, iv)
                    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
                    output_buffer.write(decrypted_data)
                    
                    # Generar nombre de archivo
                    import datetime
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    output_filename = f'texto_descifrado_{timestamp}.txt'
                    flash('Archivo descifrado exitosamente', 'success')
                
                # Enviar archivo resultado
                output_buffer.seek(0)
                return send_file(
                    output_buffer,
                    as_attachment=True,
                    download_name=output_filename,
                    mimetype='application/octet-stream'
                )
            except Exception as e:
                flash(f'Error al procesar el archivo: {str(e)}', 'error')
                return redirect(url_for('aes'))
    
    return render_template('aes.html')

@app.route('/rsa', methods=['GET', 'POST'])
def rsa():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'generate_keys':
            try:
                # Generar par de claves RSA
                private_key, public_key = generar_claves_rsa()
                
                # Serializar las claves
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                # Crear nombres de archivo con timestamp
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                
                # Crear un archivo ZIP con ambas claves
                from io import BytesIO
                zip_buffer = BytesIO()
                import zipfile
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    zip_file.writestr(f'rsa_private_{timestamp}.pem', private_pem)
                    zip_file.writestr(f'rsa_public_{timestamp}.pem', public_pem)
                
                zip_buffer.seek(0)
                flash('Par de claves RSA generadas exitosamente', 'success')
                return send_file(
                    zip_buffer,
                    as_attachment=True,
                    download_name=f'rsa_keys_{timestamp}.zip',
                    mimetype='application/zip'
                )
            except Exception as e:
                flash(f'Error al generar las claves: {str(e)}', 'error')
                return redirect(url_for('rsa'))
        
        elif action == 'save_text':
            try:
                # Obtener texto plano
                plaintext = request.form.get('plaintext')
                if not plaintext or not plaintext.strip():
                    flash('El texto no puede estar vacío', 'error')
                    return redirect(url_for('rsa'))
                
                # Crear nombre de archivo con timestamp
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                text_filename = f'texto_plano_{timestamp}.txt'
                
                # Enviar texto como archivo
                from io import BytesIO
                text_file = BytesIO(plaintext.encode('utf-8'))
                flash('Texto guardado exitosamente', 'success')
                return send_file(
                    text_file,
                    as_attachment=True,
                    download_name=text_filename,
                    mimetype='text/plain'
                )
            except Exception as e:
                flash(f'Error al guardar el texto: {str(e)}', 'error')
                return redirect(url_for('rsa'))
        
        elif action in ['encrypt', 'decrypt']:
            try:
                # Verificar archivos requeridos
                if 'file' not in request.files or 'key' not in request.files:
                    flash('Se requiere archivo y clave', 'error')
                    return redirect(url_for('rsa'))
                
                file = request.files['file']
                key_file = request.files['key']
                
                if file.filename == '' or key_file.filename == '':
                    flash('No se seleccionó archivo', 'error')
                    return redirect(url_for('rsa'))
                
                # Leer archivos en memoria
                file_content = file.read()
                key_content = key_file.read()
                
                # Procesar archivo
                if action == 'encrypt':
                    # Cifrar contenido
                    public_key = serialization.load_pem_public_key(key_content)
                    encrypted = cifrar_con_rsa(file_content, public_key)
                    
                    # Generar nombre de archivo
                    import datetime
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    output_filename = f'texto_cifrado_{timestamp}.enc'
                    flash('Archivo cifrado exitosamente', 'success')
                    
                    # Enviar archivo cifrado
                    from io import BytesIO
                    output_buffer = BytesIO(encrypted)
                    return send_file(
                        output_buffer,
                        as_attachment=True,
                        download_name=output_filename,
                        mimetype='application/octet-stream'
                    )
                else:
                    # Descifrar contenido
                    private_key = serialization.load_pem_private_key(key_content, password=None)
                    decrypted = descifrar_con_rsa(file_content, private_key)
                    
                    # Generar nombre de archivo
                    import datetime
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    output_filename = f'texto_descifrado_{timestamp}.txt'
                    flash('Archivo descifrado exitosamente', 'success')
                    
                    # Enviar archivo descifrado
                    from io import BytesIO
                    output_buffer = BytesIO(decrypted)
                    return send_file(
                        output_buffer,
                        as_attachment=True,
                        download_name=output_filename,
                        mimetype='text/plain'
                    )
            except Exception as e:
                flash(f'Error al procesar el archivo: {str(e)}', 'error')
                return redirect(url_for('rsa'))
    
    return render_template('rsa.html')

@app.route('/firma', methods=['GET', 'POST'])
def firma():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'generate_keys':
            try:
                # Generar par de claves RSA
                private_key, public_key = generar_claves_rsa()
                
                # Serializar las claves
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                # Crear nombres de archivo con timestamp
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                
                # Crear un archivo ZIP con ambas claves
                from io import BytesIO
                zip_buffer = BytesIO()
                import zipfile
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    zip_file.writestr(f'firma_private_{timestamp}.pem', private_pem)
                    zip_file.writestr(f'firma_public_{timestamp}.pem', public_pem)
                
                zip_buffer.seek(0)
                flash('Par de claves RSA para firma digital generadas exitosamente', 'success')
                return send_file(
                    zip_buffer,
                    as_attachment=True,
                    download_name=f'firma_keys_{timestamp}.zip',
                    mimetype='application/zip'
                )
            except Exception as e:
                flash(f'Error al generar las claves: {str(e)}', 'error')
                return redirect(url_for('firma'))
        
        elif action == 'save_text':
            try:
                # Obtener texto plano
                plaintext = request.form.get('plaintext')
                if not plaintext or not plaintext.strip():
                    flash('El texto no puede estar vacío', 'error')
                    return redirect(url_for('firma'))
                
                # Crear nombre de archivo con timestamp
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                text_filename = f'texto_original_{timestamp}.txt'
                
                # Enviar texto como archivo
                from io import BytesIO
                text_file = BytesIO(plaintext.encode('utf-8'))
                flash('Texto guardado exitosamente', 'success')
                return send_file(
                    text_file,
                    as_attachment=True,
                    download_name=text_filename,
                    mimetype='text/plain'
                )
            except Exception as e:
                flash(f'Error al guardar el texto: {str(e)}', 'error')
                return redirect(url_for('firma'))
        
        elif action == 'sign':
            try:
                # Verificar archivos requeridos
                if 'file' not in request.files or 'key' not in request.files:
                    flash('Se requiere archivo y clave privada', 'error')
                    return redirect(url_for('firma'))
                
                file = request.files['file']
                key_file = request.files['key']
                
                if file.filename == '' or key_file.filename == '':
                    flash('No se seleccionó archivo', 'error')
                    return redirect(url_for('firma'))
                
                # Leer archivos en memoria
                file_content = file.read()
                key_content = key_file.read()
                
                # Firmar contenido
                private_key = serialization.load_pem_private_key(key_content, password=None)
                signature = firmar_datos(file_content, private_key)
                
                # Generar nombre de archivo
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                sig_filename = f'firma_{timestamp}.sig'
                
                # Enviar firma como archivo
                from io import BytesIO
                sig_file = BytesIO(signature)
                flash('Archivo firmado exitosamente', 'success')
                return send_file(
                    sig_file,
                    as_attachment=True,
                    download_name=sig_filename,
                    mimetype='application/octet-stream'
                )
            except Exception as e:
                flash(f'Error al firmar el archivo: {str(e)}', 'error')
                return redirect(url_for('firma'))
        
        elif action == 'verify':
            try:
                # Verificar archivos requeridos
                if 'file' not in request.files or 'signature' not in request.files or 'key' not in request.files:
                    flash('Se requiere archivo original, firma y clave pública', 'error')
                    return redirect(url_for('firma'))
                
                file = request.files['file']
                sig_file = request.files['signature']
                key_file = request.files['key']
                
                if file.filename == '' or sig_file.filename == '' or key_file.filename == '':
                    flash('No se seleccionó archivo', 'error')
                    return redirect(url_for('firma'))
                
                # Leer archivos en memoria
                file_content = file.read()
                sig_content = sig_file.read()
                key_content = key_file.read()
                
                # Verificar firma
                public_key = serialization.load_pem_public_key(key_content)
                if verificar_firma(file_content, sig_content, public_key):
                    flash('La firma es válida. El documento es auténtico y no ha sido modificado.', 'success')
                else:
                    flash('La firma NO es válida. El documento puede haber sido modificado o la firma es incorrecta.', 'error')
                return redirect(url_for('firma'))
            except Exception as e:
                flash(f'Error al verificar la firma: {str(e)}', 'error')
                return redirect(url_for('firma'))
    
    return render_template('firma.html')

@app.route('/hash', methods=['GET', 'POST'])
def hash():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'calculate':
            try:
                # Verificar archivo requerido
                if 'file' not in request.files:
                    flash('Se requiere un archivo', 'error')
                    return redirect(url_for('hash'))
                
                file = request.files['file']
                if file.filename == '':
                    flash('No se seleccionó archivo', 'error')
                    return redirect(url_for('hash'))
                
                # Leer archivo en memoria
                file_content = file.read()
                
                # Calcular hash
                digest = hashes.Hash(hashes.SHA256())
                digest.update(file_content)
                hash_value = digest.finalize()
                
                # Crear nombre de archivo con timestamp
                import datetime
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                hash_filename = f'hash_{timestamp}.sha256'
                
                # Enviar hash como archivo
                from io import BytesIO
                hash_file = BytesIO(hash_value)
                flash('Hash calculado exitosamente', 'success')
                return send_file(
                    hash_file,
                    as_attachment=True,
                    download_name=hash_filename,
                    mimetype='application/octet-stream'
                )
            except Exception as e:
                flash(f'Error al calcular el hash: {str(e)}', 'error')
                return redirect(url_for('hash'))
        
        elif action == 'verify':
            try:
                # Verificar archivos requeridos
                if 'file' not in request.files or 'hash' not in request.files:
                    flash('Se requiere archivo original y archivo de hash', 'error')
                    return redirect(url_for('hash'))
                
                file = request.files['file']
                hash_file = request.files['hash']
                
                if file.filename == '' or hash_file.filename == '':
                    flash('No se seleccionó archivo', 'error')
                    return redirect(url_for('hash'))
                
                # Leer archivos en memoria
                file_content = file.read()
                stored_hash = hash_file.read()
                
                # Calcular hash del archivo
                digest = hashes.Hash(hashes.SHA256())
                digest.update(file_content)
                calculated_hash = digest.finalize()
                
                # Comparar hashes
                if calculated_hash == stored_hash:
                    flash('La integridad del archivo es correcta. El archivo no ha sido modificado.', 'success')
                else:
                    flash('¡ADVERTENCIA! El archivo ha sido modificado. Los hashes no coinciden.', 'error')
                return redirect(url_for('hash'))
            except Exception as e:
                flash(f'Error al verificar el hash: {str(e)}', 'error')
                return redirect(url_for('hash'))
    
    return render_template('hash.html')

if __name__ == '__main__':
    app.run(debug=True)
