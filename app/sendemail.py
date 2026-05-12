import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Configuración SMTP
smtp_server = 'smtppro.zoho.com'
smtp_port = 587
email_address = 'soporte@pctintas.com'
password = 'q7sU2re0Qr84'  # Tu contraseña de aplicación

def enviar_correo_garantia(datos_orden):
    """
    Envía un correo con los datos de la garantía.
    
    datos_orden: diccionario con los datos de la garantía:
        - cliente: nombre del cliente
        - numero_recibo: ID de la garantía
        - fecha: fecha de registro
        - usuario: técnico que registra
        - marca: marca del producto
        - modelo: modelo del producto
        - serial: serial del producto
        - fallo: descripción de la falla
        - email: correo del cliente (destinatario)
    """
    
    # --- Cargar el archivo HTML (debe estar en la carpeta static) ---
    template_path = os.path.join(os.path.dirname(__file__), 'static', 'orden_garantia_template.html')
    try:
        with open(template_path, 'r', encoding='utf-8') as file:
            html_template = file.read()
        #print("✅ Archivo HTML cargado correctamente")
    except FileNotFoundError:
        #print("❌ Error: No se encontró el archivo 'orden_garantia_template.html'")
        return False

    # Reemplazar las variables en el HTML
    for clave, valor in datos_orden.items():
        html_template = html_template.replace(f'[{clave}]', str(valor))

    # Crear el mensaje
    msg = MIMEMultipart()
    msg['From'] = email_address
    msg['To'] = datos_orden.get('email', '')
    numero_orden = datos_orden.get("NUMERO_ORDEN") or datos_orden.get("numero_orden") or datos_orden.get("numero_recibo") or ""
    nombre_cliente = datos_orden.get("NOMBRE_CLIENTE") or datos_orden.get("cliente") or ""
    msg['Subject'] = f'🔧 Orden de Servicio #{numero_orden} - {nombre_cliente}'

    # Adjuntar el HTML personalizado
    msg.attach(MIMEText(html_template, 'html', 'utf-8'))

    # Enviar el correo
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email_address, password)
            server.send_message(msg)
        #print("✅ Correo enviado exitosamente")
        return True
    except Exception as e:
        #print(f"❌ Error al enviar el correo: {e}")
        return False
