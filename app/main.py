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

# GARANTIAS
@app.post("/api/garantias")
async def crear_garantia_api(
    cliente: str = Form(...),
    cedula: Optional[str] = Form(None),
    producto: str = Form(...),
    factura: Optional[str] = Form(None),
    fecha_compra: Optional[str] = Form(None),
    descripcion_falla: Optional[str] = Form(None),
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
    nueva = Garantia(cliente=cliente, cedula=cedula, producto=producto, factura=factura, fecha_compra=fecha_compra, descripcion_falla=descripcion_falla, imagen_path=imagen_path, estado="Pendiente")
    db.add(nueva)
    db.commit()
    db.refresh(nueva)
    return {"id": nueva.id, "cliente": nueva.cliente, "cedula": nueva.cedula, "producto": nueva.producto, "estado": nueva.estado, "fecha_registro": nueva.fecha_registro.isoformat()}

@app.get("/api/garantias")
def listar_garantias_api(db: Session = Depends(get_db), token: str = Header(None)):
    verify_token(token)
    items = db.query(Garantia).order_by(Garantia.id.desc()).all()
    out = []
    for g in items:
        out.append({"id": g.id, "cliente": g.cliente, "cedula": g.cedula, "producto": g.producto, "factura": g.factura, "fecha_compra": g.fecha_compra, "descripcion_falla": g.descripcion_falla, "imagen_path": g.imagen_path, "estado": g.estado, "fecha_registro": g.fecha_registro.isoformat()})
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
        rows.append({"id": g.id, "cliente": g.cliente, "cedula": g.cedula, "producto": g.producto, "factura": g.factura, "fecha_compra": g.fecha_compra, "descripcion_falla": g.descripcion_falla, "estado": g.estado, "fecha_registro": g.fecha_registro.isoformat()})
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
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from io import BytesIO
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Estilos personalizados
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=20,
        spaceAfter=30,
        alignment=1  # Centrado
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=20,
        alignment=1
    )
    
    normal_style = styles['Normal']
    normal_style.spaceAfter = 10
    
    # Contenido del PDF
    content = []
    
    # Título
    content.append(Paragraph("RECIBO DE GARANTÍA", title_style))
    content.append(Spacer(1, 20))
    
    # Información de la empresa
    empresa_info = [
        [f"Empresa: {config.nombre_empresa}"],
        [f"Teléfono: {config.telefono or 'N/A'}"],
        [f"Email: {config.email or 'N/A'}"],
        [f"Dirección: {config.direccion or 'N/A'}"],
        [f"Ciudad: {config.ciudad or 'N/A'}"],
        [f"NIT: {config.nit or 'N/A'}"]
    ]
    
    empresa_table = Table(empresa_info, colWidths=[6*inch])
    empresa_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    content.append(empresa_table)
    content.append(Spacer(1, 20))
    
    # Fecha y número de recibo
    content.append(Paragraph(f"Fecha de emisión: {datetime.utcnow().strftime('%d/%m/%Y %H:%M')}", normal_style))
    content.append(Paragraph(f"Número de garantía: #{garantia.id}", normal_style))
    content.append(Paragraph(f"Usuario que registra: {usuario_registro}", normal_style))
    content.append(Spacer(1, 20))
    
    # Información de la garantía
    content.append(Paragraph("DETALLE DE LA GARANTÍA", subtitle_style))
    
    garantia_info = [
        ["Cliente:", garantia.cliente],
        ["Cédula:", garantia.cedula or "N/A"],
        ["Producto:", garantia.producto],
        ["Factura:", garantia.factura or "N/A"],
        ["Fecha de compra:", garantia.fecha_compra or "N/A"],
        ["Descripción de falla:", garantia.descripcion_falla or "N/A"],
        ["Estado:", garantia.estado],
        ["Fecha de registro:", garantia.fecha_registro.strftime('%d/%m/%Y %H:%M')]
    ]
    
    garantia_table = Table(garantia_info, colWidths=[2*inch, 4*inch])
    garantia_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    content.append(garantia_table)
    content.append(Spacer(1, 20))
    
    # Términos y condiciones
    content.append(Paragraph("TÉRMINOS Y CONDICIONES", subtitle_style))
    terminos = """
    1. Esta garantía es válida por el período establecido por el fabricante.
    2. La garantía cubre defectos de fabricación, no daños por uso indebido.
    3. Para hacer efectiva la garantía, presente este recibo junto con el producto.
    4. El tiempo de reparación puede variar según la disponibilidad de repuestos.
    5. Esta garantía no incluye daños por transporte o instalación incorrecta.
    """
    content.append(Paragraph(terminos, normal_style))
    content.append(Spacer(1, 20))
    
    # Firma
    content.append(Paragraph("______________________________", ParagraphStyle('Firma', parent=normal_style, alignment=1)))
    content.append(Paragraph("Firma del cliente", ParagraphStyle('FirmaLabel', parent=normal_style, alignment=1, spaceAfter=30)))
    
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
