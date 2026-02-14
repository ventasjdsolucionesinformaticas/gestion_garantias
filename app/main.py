import os, uuid, shutil
from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException, Depends, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import Garantia, Comentario, Usuario, ConfiguracionEmpresa
from pydantic import BaseModel
from typing import Optional
from security import create_token, verify_token
from sqlalchemy.exc import IntegrityError
from datetime import datetime

# create tables
Base.metadata.create_all(bind=engine)

# Migración: añadir columna email a garantias si no existe
def ensure_email_column():
    from sqlalchemy import text
    with engine.connect() as conn:
        try:
            r = conn.execute(text("PRAGMA table_info(garantias)"))
            cols = [row[1] for row in r.fetchall()]
            if "email" not in cols:
                conn.execute(text("ALTER TABLE garantias ADD COLUMN email VARCHAR"))
                conn.commit()
        except Exception:
            pass
ensure_email_column()

app = FastAPI(title="Garantías JD Soluciones - v3.4", version="3.4", docs_url="/docs", redoc_url="/redoc", openapi_url="/openapi.json")

UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return FileResponse("static/index.html", media_type="text/html")

class LoginIn(BaseModel):
    username: str
    password: str

class UsuarioIn(BaseModel):
    username: str
    password: str
    rol: str = "tecnico"

class UsuarioUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    rol: Optional[str] = None

class EmpresaConfig(BaseModel):
    nombre_empresa: str = "JD Soluciones"
    telefono: Optional[str] = None
    email: Optional[str] = None
    direccion: Optional[str] = None
    ciudad: Optional[str] = None
    nit: Optional[str] = None

class EmpresaConfigUpdate(BaseModel):
    nombre_empresa: Optional[str] = None
    telefono: Optional[str] = None
    email: Optional[str] = None
    direccion: Optional[str] = None
    ciudad: Optional[str] = None
    nit: Optional[str] = None

# init admin
def init_admin():
    db = SessionLocal()
    if not db.query(Usuario).filter(Usuario.username=="admin").first():
        admin = Usuario(username="admin", password_hash="$2b$12$invalidplaceholder", rol="admin")
        # set real hash now
        from passlib.context import CryptContext
        pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
        admin.password_hash = pwd.hash("admin123")
        db.add(admin)
        try:
            db.commit()
        except:
            db.rollback()
    db.close()

def init_empresa_config():
    db = SessionLocal()
    if not db.query(ConfiguracionEmpresa).first():
        config = ConfiguracionEmpresa(
            nombre_empresa="JD Soluciones",
            telefono="+57 300 123 4567",
            email="contacto@jdsoluciones.com",
            direccion="Calle 123 #45-67",
            ciudad="Bogotá, Colombia",
            nit="901.234.567-8"
        )
        db.add(config)
        try:
            db.commit()
        except:
            db.rollback()
    db.close()

init_admin()
init_empresa_config()

@app.post("/api/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(Usuario).filter(Usuario.username==data.username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    from passlib.context import CryptContext
    pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
    if not pwd.verify(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    token = create_token(user.username)
    return {"token": token, "username": user.username, "rol": user.rol}

# USERS - admin only
@app.get("/api/usuarios")
def listar_usuarios(token: str = Header(None), db: Session = Depends(get_db)):
    username = verify_token(token)
    dbuser = db.query(Usuario).filter(Usuario.username==username).first()
    if not dbuser or dbuser.rol != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede ver usuarios")
    users = db.query(Usuario).all()
    return [{"id": u.id, "username": u.username, "rol": u.rol, "fecha_creacion": u.fecha_creacion.isoformat()} for u in users]

@app.post("/api/usuarios")
def crear_usuario(u: UsuarioIn, token: str = Header(None), db: Session = Depends(get_db)):
    username = verify_token(token)
    dbuser = db.query(Usuario).filter(Usuario.username==username).first()
    if not dbuser or dbuser.rol != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede crear usuarios")
    from passlib.context import CryptContext
    pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
    nuevo = Usuario(username=u.username, password_hash=pwd.hash(u.password), rol=u.rol)
    db.add(nuevo)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    return {"mensaje": "Usuario creado"}

@app.put("/api/usuarios/{user_id}")
def actualizar_usuario(user_id: int, u: UsuarioUpdate, token: str = Header(None), db: Session = Depends(get_db)):
    username = verify_token(token)
    dbuser = db.query(Usuario).filter(Usuario.username==username).first()
    if not dbuser or dbuser.rol != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede actualizar usuarios")
    
    usuario = db.query(Usuario).filter(Usuario.id == user_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # No permitir cambiar el rol del admin principal
    if usuario.username == "admin" and u.rol and u.rol != "admin":
        raise HTTPException(status_code=400, detail="No se puede cambiar el rol del administrador principal")
    
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
    
    if u.username:
        # Verificar que el nuevo username no exista
        existing = db.query(Usuario).filter(Usuario.username == u.username, Usuario.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="El nombre de usuario ya existe")
        usuario.username = u.username
    
    if u.password:
        usuario.password_hash = pwd_context.hash(u.password)
    
    if u.rol:
        usuario.rol = u.rol
    
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error al actualizar usuario")
    
    return {"mensaje": "Usuario actualizado"}

@app.delete("/api/usuarios/{user_id}")
def eliminar_usuario(user_id: int, token: str = Header(None), db: Session = Depends(get_db)):
    username = verify_token(token)
    dbuser = db.query(Usuario).filter(Usuario.username==username).first()
    if not dbuser or dbuser.rol != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede eliminar usuarios")
    
    usuario = db.query(Usuario).filter(Usuario.id == user_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # No permitir eliminar el admin principal
    if usuario.username == "admin":
        raise HTTPException(status_code=400, detail="No se puede eliminar el administrador principal")
    
    db.delete(usuario)
    try:
        db.commit()
    except:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error al eliminar usuario")
    
    return {"mensaje": "Usuario eliminado"}

# CONFIGURACIÓN DE EMPRESA (solo admin)
@app.get("/api/configuracion-empresa/nombre")
def obtener_nombre_empresa(token: str = Header(None), db: Session = Depends(get_db)):
    """Devuelve solo el nombre de la empresa para título/navbar (cualquier usuario autenticado)."""
    verify_token(token)
    config = db.query(ConfiguracionEmpresa).first()
    return {"nombre_empresa": config.nombre_empresa if config else "Empresa"}

@app.get("/api/configuracion-empresa")
def obtener_configuracion_empresa(token: str = Header(None), db: Session = Depends(get_db)):
    username = verify_token(token)
    dbuser = db.query(Usuario).filter(Usuario.username==username).first()
    if not dbuser or dbuser.rol != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede ver configuración")
    
    config = db.query(ConfiguracionEmpresa).first()
    if not config:
        raise HTTPException(status_code=404, detail="Configuración no encontrada")
    
    return {
        "id": config.id,
        "nombre_empresa": config.nombre_empresa,
        "telefono": config.telefono,
        "email": config.email,
        "direccion": config.direccion,
        "ciudad": config.ciudad,
        "nit": config.nit,
        "logo_path": config.logo_path,
        "fecha_actualizacion": config.fecha_actualizacion.isoformat()
    }

@app.put("/api/configuracion-empresa")
def actualizar_configuracion_empresa(config: EmpresaConfigUpdate, token: str = Header(None), db: Session = Depends(get_db)):
    username = verify_token(token)
    dbuser = db.query(Usuario).filter(Usuario.username==username).first()
    if not dbuser or dbuser.rol != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede actualizar configuración")
    
    empresa_config = db.query(ConfiguracionEmpresa).first()
    if not empresa_config:
        empresa_config = ConfiguracionEmpresa()
        db.add(empresa_config)
    
    if config.nombre_empresa is not None:
        empresa_config.nombre_empresa = config.nombre_empresa
    if config.telefono is not None:
        empresa_config.telefono = config.telefono
    if config.email is not None:
        empresa_config.email = config.email
    if config.direccion is not None:
        empresa_config.direccion = config.direccion
    if config.ciudad is not None:
        empresa_config.ciudad = config.ciudad
    if config.nit is not None:
        empresa_config.nit = config.nit
    
    try:
        db.commit()
    except:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error al actualizar configuración")
    
    return {"mensaje": "Configuración actualizada"}

@app.post("/api/configuracion-empresa/logo")
async def subir_logo_empresa(logo: UploadFile = File(...), token: str = Header(None), db: Session = Depends(get_db)):
    username = verify_token(token)
    dbuser = db.query(Usuario).filter(Usuario.username==username).first()
    if not dbuser or dbuser.rol != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede subir logo")
    
    if not logo.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="El archivo debe ser una imagen")
    
    ext = os.path.splitext(logo.filename)[1]
    filename = f"logo{ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(logo.file, buffer)
    
    empresa_config = db.query(ConfiguracionEmpresa).first()
    if not empresa_config:
        empresa_config = ConfiguracionEmpresa()
        db.add(empresa_config)
    
    empresa_config.logo_path = f"/uploads/{filename}"
    
    try:
        db.commit()
    except:
        db.rollback()
        raise HTTPException(status_code=400, detail="Error al guardar logo")
    
    return {"mensaje": "Logo subido", "logo_path": empresa_config.logo_path}

# GARANTIAS
@app.post("/api/garantias")
async def crear_garantia_api(
    cliente: str = Form(...),
    cedula: str = Form(...),
    telefono: str = Form(...),
    email: Optional[str] = Form(None),
    tipo_producto: str = Form(...),
    marca: Optional[str] = Form(None),
    modelo: Optional[str] = Form(None),
    serial: Optional[str] = Form(None),
    factura: Optional[str] = Form(None),
    fecha_compra: Optional[str] = Form(None),
    descripcion_falla: str = Form(...),
    imagen: Optional[UploadFile] = File(None),
    token: str = Header(None),
    db: Session = Depends(get_db)
):
    username = verify_token(token)
    imagen_path = None
    if imagen:
        ext = os.path.splitext(imagen.filename)[1]
        filename = f"{uuid.uuid4().hex}{ext}"
        file_path = os.path.join(UPLOAD_DIR, filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(imagen.file, buffer)
        imagen_path = f"/uploads/{filename}"
    nueva = Garantia(cliente=cliente, cedula=cedula, telefono=telefono, email=email, tipo_producto=tipo_producto, marca=marca, modelo=modelo, serial=serial, factura=factura, fecha_compra=fecha_compra, descripcion_falla=descripcion_falla, imagen_path=imagen_path, estado="Recibido")
    db.add(nueva)
    db.commit()
    db.refresh(nueva)
    return {"id": nueva.id, "cliente": nueva.cliente, "cedula": nueva.cedula, "telefono": nueva.telefono, "email": nueva.email, "tipo_producto": nueva.tipo_producto, "marca": nueva.marca, "modelo": nueva.modelo, "serial": nueva.serial, "estado": nueva.estado, "fecha_registro": nueva.fecha_registro.isoformat()}

@app.get("/api/garantias")
def listar_garantias_api(db: Session = Depends(get_db), token: str = Header(None)):
    verify_token(token)
    items = db.query(Garantia).order_by(Garantia.id.desc()).all()
    out = []
    for g in items:
        out.append({"id": g.id, "cliente": g.cliente, "cedula": g.cedula, "telefono": g.telefono, "email": g.email, "tipo_producto": g.tipo_producto, "marca": g.marca, "modelo": g.modelo, "serial": g.serial, "factura": g.factura, "fecha_compra": g.fecha_compra, "descripcion_falla": g.descripcion_falla, "imagen_path": g.imagen_path, "estado": g.estado, "fecha_registro": g.fecha_registro.isoformat()})
    return out

# comentarios con adjunto
@app.post("/api/garantias/{gid}/comentarios")
async def agregar_comentario(gid: int, texto: str = Form(...), archivo: Optional[UploadFile] = File(None), token: str = Header(None), db: Session = Depends(get_db)):
    user = verify_token(token)
    garantia = db.query(Garantia).filter(Garantia.id == gid).first()
    if not garantia:
        raise HTTPException(status_code=404, detail="Garantía no encontrada")
    attachment_path = None
    if archivo:
        ext = os.path.splitext(archivo.filename)[1]
        filename = f"{uuid.uuid4().hex}{ext}"
        file_path = os.path.join(UPLOAD_DIR, filename)
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(archivo.file, buffer)
        attachment_path = f"/uploads/{filename}"
    nuevo = Comentario(garantia_id=gid, usuario=user, texto=texto, attachment_path=attachment_path)
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return {"mensaje": "Comentario agregado", "comentario": {"usuario": nuevo.usuario, "texto": nuevo.texto, "attachment_path": nuevo.attachment_path, "fecha": nuevo.fecha.isoformat()}}

@app.get("/api/garantias/{gid}/comentarios")
def listar_comentarios(gid: int, token: str = Header(None), db: Session = Depends(get_db)):
    verify_token(token)
    comentarios = db.query(Comentario).filter(Comentario.garantia_id == gid).order_by(Comentario.id.asc()).all()
    return [{"usuario": c.usuario, "texto": c.texto, "attachment_path": c.attachment_path, "fecha": c.fecha.isoformat()} for c in comentarios]

@app.patch("/api/garantias/{gid}/estado")
def cambiar_estado(gid: int, estado: str = Form(...), token: str = Header(None), db: Session = Depends(get_db)):
    user = verify_token(token)
    u = db.query(Usuario).filter(Usuario.username == user).first()
    if not u:
        raise HTTPException(status_code=401, detail="Usuario inválido")
    if u.rol not in ["admin", "tecnico"]:
        raise HTTPException(status_code=403, detail="No tiene permiso para cambiar estado")
    garantia = db.query(Garantia).filter(Garantia.id == gid).first()
    if not garantia:
        raise HTTPException(status_code=404, detail="Garantía no encontrada")
    garantia.estado = estado
    db.commit()
    return {"mensaje": "Estado actualizado", "estado": garantia.estado}

# export to excel (admin only)
@app.get("/api/garantias/export")
def export_garantias(token: str = Header(None), db: Session = Depends(get_db)):
    user = verify_token(token)
    u = db.query(Usuario).filter(Usuario.username == user).first()
    if not u or u.rol != "admin":
        raise HTTPException(status_code=403, detail="Solo admin puede exportar")
    import pandas as pd
    items = db.query(Garantia).order_by(Garantia.id.desc()).all()
    rows = []
    for g in items:
        rows.append({"id": g.id, "cliente": g.cliente, "cedula": g.cedula, "telefono": g.telefono, "email": g.email, "tipo_producto": g.tipo_producto, "marca": g.marca, "modelo": g.modelo, "serial": g.serial, "factura": g.factura, "fecha_compra": g.fecha_compra, "descripcion_falla": g.descripcion_falla, "estado": g.estado, "fecha_registro": g.fecha_registro.isoformat()})
    df = pd.DataFrame(rows)
    out_path = os.path.join("data", f"garantias_export_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.xlsx")
    df.to_excel(out_path, index=False)
    return FileResponse(out_path, filename=os.path.basename(out_path), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# RECIBO DE GARANTÍA
@app.get("/api/garantias/{gid}/recibo")
def generar_recibo(gid: int, token: str = Header(None), db: Session = Depends(get_db)):
    username = verify_token(token)
    
    garantia = db.query(Garantia).filter(Garantia.id == gid).first()
    if not garantia:
        raise HTTPException(status_code=404, detail="Garantía no encontrada")
    
    # Obtener configuración de empresa
    config = db.query(ConfiguracionEmpresa).first()
    if not config:
        config = ConfiguracionEmpresa()  # Valores por defecto
    
    # Obtener usuario que generó la garantía (del primer comentario o del registro)
    usuario_registro = username  # Por defecto el usuario actual
    
    # Generar PDF del recibo
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from io import BytesIO
    
    # Tamaño media carta (8.5 x 5.5 pulgadas)
    half_letter = (8.5*inch, 5.5*inch)
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=half_letter,
        topMargin=0.1*inch,  # Margen superior más mínimo
        bottomMargin=0.1*inch,
        leftMargin=0.5*inch,
        rightMargin=0.5*inch
    )
    styles = getSampleStyleSheet()
    
    # Estilos personalizados
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=10,
        spaceAfter=3,
        alignment=1  # Centrado
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=20,
        alignment=1
    )
    
    small_style = ParagraphStyle(
        'SmallText',
        parent=styles['Normal'],
        fontSize=9, # Aumentado de 6 a 8
        spaceAfter=0,
        leading=11,  # Aumentado para mejorar el interlineado
        alignment=0  # Alinear a la izquierda para el texto de la empresa
    )
    
    normal_style = styles['Normal']
    normal_style.spaceAfter = 10
    
    # Estilo para política de garantía: letra muy pequeña, justificado
    policy_style = ParagraphStyle(
        'PolicyText',
        parent=styles['Normal'],
        fontSize=5,
        leading=6,
        alignment=4,  # 4 = JUSTIFY en ReportLab
        spaceBefore=4,
        spaceAfter=4,
        leftIndent=0,
        rightIndent=0,
    )
    
    # Contenido del PDF
    content = []
    
    # Header con logo y datos de empresa lado a lado
    logo_cell = []
    company_info_paragraph = []
    
    if config.logo_path and config.logo_path is not None:
        try:
            logo_path = os.path.join(os.getcwd(), config.logo_path.lstrip('/'))
            if os.path.exists(logo_path):
                logo = Image(logo_path, width=1*inch, height=1*inch)
                logo_cell.append(logo)
        except Exception as e:
            pass  # Ignorar error si no se puede cargar logo

    company_info_text = []
    if config.nombre_empresa:
        company_info_text.append(config.nombre_empresa)
    if config.telefono:
        company_info_text.append(f"Tel: {config.telefono}")
    if config.email:
        company_info_text.append(config.email)
    if config.direccion:
        company_info_text.append(config.direccion)
    if config.ciudad:
        company_info_text.append(config.ciudad)
    if config.nit:
        company_info_text.append(f"NIT: {config.nit}")
    
    if company_info_text:
        company_info_paragraph = [Paragraph("<br/>".join(company_info_text), small_style)]
    
    # Solo crear tabla de header si hay algo que mostrar
    if logo_cell or company_info_paragraph:
        # Ancho total disponible para contenido (half_letter ancho - leftMargin - rightMargin)
        available_width = half_letter[0] - (doc.leftMargin + doc.rightMargin)
        
        # Calcular anchos de columna para la tabla del encabezado
        # Una columna para el logo, otra para la información de la empresa
        logo_width = 1.0 * inch 
        info_width = available_width - logo_width - 0.1*inch
        
        # Asegurar que logo_cell y company_info_paragraph estén listos para la tabla
        logo_cell_for_table = logo_cell if logo_cell else []
        info_cell_for_table = company_info_paragraph if company_info_paragraph else [Paragraph("", small_style)]
        
        header_table_data = [[logo_cell_for_table, info_cell_for_table]]
        
        header_table = Table(header_table_data, colWidths=[logo_width, info_width], hAlign='LEFT')
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (1, 0), (1, 0), 0.1*inch),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (0, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ]))
        content.append(header_table)
        content.append(Spacer(1, 2))
    
    # Título
    content.append(Spacer(1, 8))
    content.append(Paragraph(f"RECIBO DE GARANTÍA #{garantia.id}", title_style))
    content.append(Spacer(1, 3))
    
    # Información básica en tabla
    data = []
    
    # Agregar filas de datos
    data.append(["Fecha:", datetime.utcnow().strftime('%d/%m/%Y')])
    data.append(["Cliente:", garantia.cliente])
    if garantia.telefono:
        data.append(["Teléfono:", garantia.telefono])
    if garantia.email:
        data.append(["Email:", garantia.email])

    # Combinar producto en una sola línea
    producto_parts = []
    if garantia.tipo_producto:
        producto_parts.append(garantia.tipo_producto)
    if garantia.marca:
        producto_parts.append(garantia.marca)
    if garantia.modelo:
        producto_parts.append(garantia.modelo)
    producto_desc = " ".join(producto_parts)
    if producto_desc:
        data.append(["Producto:", producto_desc])
    
    if garantia.serial:
        data.append(["Serial:", garantia.serial])
    if garantia.factura:
        data.append(["Factura:", garantia.factura])
    data.append(["Usuario:", usuario_registro])
    if garantia.descripcion_falla:
        data.append(["Fallo:", garantia.descripcion_falla])
    data.append(["Estado:", garantia.estado])
    
    # Crear tabla
    table = Table(data, colWidths=[1.5*inch, 3.5*inch])  # Reducido para media carta
    
    # Construir estilos dinámicamente basado en el número real de filas
    table_styles = [
        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 3),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
    ]
    
    # Agregar fondos alternos solo para filas que existen
    num_rows = len(data)
    for i in range(1, num_rows, 2):  # Filas impares con fondo gris
        table_styles.append(('BACKGROUND', (0, i), (-1, i), colors.whitesmoke))
    
    table.setStyle(TableStyle(table_styles))
    
    content.append(table)
    content.append(Spacer(1, 6))
    
    # Política de garantía (texto justificado, letra muy pequeña)
    politica_texto = (
        "EL PRESENTE DOCUMENTO NO SIGNIFICA QUE ACEPTAMOS LA GARANTÍA; SIGNIFICA QUE ESTAMOS RECIBIENDO EL EQUIPO "
        "PARA REVISARLO Y CONFIRMAR SI APLICA O NO DICHA GARANTÍA. Después de 30 días a partir de la fecha, se cobrará "
        "bodegaje a razón de quinientos pesos ($500) por día. Transcurridos 90 días, se considera que el dispositivo ha "
        "sido abandonado. En caso de pérdida o daño por fuerza mayor no se responderá por el mismo."
    )
    content.append(Paragraph(politica_texto, policy_style))
    content.append(Spacer(1, 4))
    
    # Firma
    content.append(Paragraph("______________________________", ParagraphStyle('Firma', parent=normal_style, alignment=1)))
    content.append(Paragraph("Firma del cliente", ParagraphStyle('FirmaLabel', parent=normal_style, alignment=1, spaceAfter=10)))
    
    # Generar PDF
    doc.build(content)
    buffer.seek(0)
    
    # Guardar en archivo temporal
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
        tmp_file.write(buffer.getvalue())
        tmp_path = tmp_file.name
    
    return FileResponse(
        tmp_path, 
        media_type='application/pdf',
        filename=f'recibo_garantia_{garantia.id}.pdf'
    )
