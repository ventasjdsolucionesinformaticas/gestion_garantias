import os, uuid, shutil
from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException, Depends, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import Garantia, Comentario, Usuario, ConfiguracionEmpresa, now_colombia
from pydantic import BaseModel
from typing import Optional
from security import create_token, verify_token
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from sendemail import enviar_correo_garantia

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

# USERS - endpoint público para obtener lista de usuarios (para selects)
@app.get("/api/usuarios-lista")
def listar_usuarios_publico(token: str = Header(None), db: Session = Depends(get_db)):
    verify_token(token)  # Solo verificar que tenga token válido, sin restricción de rol
    users = db.query(Usuario).all()
    return [{"id": u.id, "username": u.username, "rol": u.rol} for u in users]

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
    usuario_asignado: Optional[str] = Form(None),
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
    
    # Si no se especifica usuario_asignado, asignar al usuario que crea la garantía
    asignado_a = usuario_asignado if usuario_asignado else username
    
    nueva = Garantia(cliente=cliente, cedula=cedula, telefono=telefono, email=email, tipo_producto=tipo_producto, marca=marca, modelo=modelo, serial=serial, factura=factura, fecha_compra=fecha_compra, descripcion_falla=descripcion_falla, imagen_path=imagen_path, usuario_asignado=asignado_a, estado="Recibido")
    db.add(nueva)
    db.commit()
    db.refresh(nueva)
    
    # Enviar correo con los datos de la garantía (si hay email del cliente)
    email_enviado = False
    print(f"[DEBUG] nueva.id después de refresh: {nueva.id!r}")
    if email:
        try:
            datos_correo = {
                'NOMBRE_CLIENTE': cliente,
                'NUMERO_ORDEN': str(nueva.id) if nueva.id is not None else '',
                'FECHA_EMISION': nueva.fecha_registro.strftime('%d/%m/%Y') if nueva.fecha_registro else '',
                'TECNICO': username,
                'PRODUCTO_1': marca or '',
                'MARCA_MODELO_1': modelo or '',
                'SERIE_1': serial or '',
                'FALLA_1': descripcion_falla,
                'email': email
            }
            email_enviado = enviar_correo_garantia(datos_correo)
        except Exception as e:
            # Si falla el envío, no fallamos toda la operación
            print(f"Error al enviar correo: {e}")
    
    return {"id": nueva.id, "cliente": nueva.cliente, "cedula": nueva.cedula, "telefono": nueva.telefono, "email": nueva.email, "tipo_producto": nueva.tipo_producto, "marca": nueva.marca, "modelo": nueva.modelo, "serial": nueva.serial, "usuario_asignado": nueva.usuario_asignado, "estado": nueva.estado, "fecha_registro": nueva.fecha_registro.isoformat(), "email_enviado": email_enviado}

@app.get("/api/garantias/{gid}")
def obtener_garantia_api(gid: int, db: Session = Depends(get_db), token: str = Header(None)):
    verify_token(token)  # Solo verificar token, sin restricción de permisos para leer detalles
    garantia = db.query(Garantia).filter(Garantia.id == gid).first()
    if not garantia:
        raise HTTPException(status_code=404, detail="Garantía no encontrada")
    return {"id": garantia.id, "cliente": garantia.cliente, "cedula": garantia.cedula, "telefono": garantia.telefono, "email": garantia.email, "tipo_producto": garantia.tipo_producto, "marca": garantia.marca, "modelo": garantia.modelo, "serial": garantia.serial, "factura": garantia.factura, "fecha_compra": garantia.fecha_compra, "descripcion_falla": garantia.descripcion_falla, "imagen_path": garantia.imagen_path, "usuario_asignado": garantia.usuario_asignado, "estado": garantia.estado, "valor_cobrado": garantia.valor_cobrado, "fecha_registro": garantia.fecha_registro.isoformat()}

@app.get("/api/garantias")
def listar_garantias_api(db: Session = Depends(get_db), token: str = Header(None)):
    username = verify_token(token)
    
    # Todos los usuarios pueden ver todas las garantías
    # Las restricciones de modificación se aplican en otros endpoints
    items = db.query(Garantia).order_by(Garantia.id.desc()).all()
    
    out = []
    for g in items:
        out.append({"id": g.id, "cliente": g.cliente, "cedula": g.cedula, "telefono": g.telefono, "email": g.email, "tipo_producto": g.tipo_producto, "marca": g.marca, "modelo": g.modelo, "serial": g.serial, "factura": g.factura, "fecha_compra": g.fecha_compra, "descripcion_falla": g.descripcion_falla, "imagen_path": g.imagen_path, "usuario_asignado": g.usuario_asignado, "estado": g.estado, "valor_cobrado": g.valor_cobrado, "fecha_registro": g.fecha_registro.isoformat()})
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
    
    # Solo admin y técnico pueden cambiar estado
    if u.rol not in ["admin", "tecnico"]:
        raise HTTPException(status_code=403, detail="No tiene permiso para cambiar estado")
    
    garantia = db.query(Garantia).filter(Garantia.id == gid).first()
    if not garantia:
        raise HTTPException(status_code=404, detail="Garantía no encontrada")
    
    # Si es técnico, solo puede cambiar sus propias garantías
    if u.rol == "tecnico" and garantia.usuario_asignado != user:
        raise HTTPException(status_code=403, detail="Solo puede cambiar estado de sus propias garantías")
    
    garantia.estado = estado
    db.commit()
    return {"mensaje": "Estado actualizado", "estado": garantia.estado}

@app.patch("/api/garantias/{gid}/valor")
def actualizar_valor_cobrado(gid: int, valor: float = Form(...), token: str = Header(None), db: Session = Depends(get_db)):
    user = verify_token(token)
    u = db.query(Usuario).filter(Usuario.username == user).first()
    if not u:
        raise HTTPException(status_code=401, detail="Usuario inválido")
    if u.rol not in ["admin", "tecnico"]:
        raise HTTPException(status_code=403, detail="No tiene permiso para registrar valor")
    garantia = db.query(Garantia).filter(Garantia.id == gid).first()
    if not garantia:
        raise HTTPException(status_code=404, detail="Garantía no encontrada")
    garantia.valor_cobrado = valor
    db.commit()
    return {"mensaje": "Valor actualizado", "valor_cobrado": garantia.valor_cobrado}

# Búsqueda de clientes existentes para autocompletado
@app.get("/api/clientes/buscar")
def buscar_clientes(q: str = "", token: str = Header(None), db: Session = Depends(get_db)):
    verify_token(token)
    if not q or len(q) < 2:
        return []
    resultados = (
        db.query(Garantia.cliente, Garantia.cedula, Garantia.telefono, Garantia.email)
        .filter(
            (Garantia.cliente.ilike(f"%{q}%")) | (Garantia.cedula.ilike(f"%{q}%"))
        )
        .distinct()
        .order_by(Garantia.cliente)
        .limit(8)
        .all()
    )
    vistos = set()
    out = []
    for r in resultados:
        key = (r.cliente, r.cedula)
        if key not in vistos:
            vistos.add(key)
            out.append({"cliente": r.cliente, "cedula": r.cedula or "", "telefono": r.telefono or "", "email": r.email or ""})
    return out

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
    out_path = os.path.join("data", f"garantias_export_{now_colombia().strftime('%Y%m%d%H%M%S')}.xlsx")
    df.to_excel(out_path, index=False)
    return FileResponse(out_path, filename=os.path.basename(out_path), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# EDITAR DATOS DE CLIENTE EN GARANTÍA (admin y técnico asignado)
@app.patch("/api/garantias/{gid}/cliente")
def editar_cliente_garantia(
    gid: int,
    cliente: Optional[str] = Form(None),
    cedula: Optional[str] = Form(None),
    telefono: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    token: str = Header(None),
    db: Session = Depends(get_db)
):
    user = verify_token(token)
    u = db.query(Usuario).filter(Usuario.username == user).first()
    if not u:
        raise HTTPException(status_code=401, detail="Usuario inválido")
    if u.rol not in ["admin", "tecnico"]:
        raise HTTPException(status_code=403, detail="No tiene permiso para editar")
    garantia = db.query(Garantia).filter(Garantia.id == gid).first()
    if not garantia:
        raise HTTPException(status_code=404, detail="Garantía no encontrada")
    if u.rol == "tecnico" and garantia.usuario_asignado != user:
        raise HTTPException(status_code=403, detail="Solo puede editar sus propias garantías")
    if cliente is not None and cliente.strip():
        garantia.cliente = cliente.strip()
    if cedula is not None and cedula.strip():
        garantia.cedula = cedula.strip()
    if telefono is not None and telefono.strip():
        garantia.telefono = telefono.strip()
    if email is not None:
        garantia.email = email.strip() or None
    db.commit()
    return {"mensaje": "Datos del cliente actualizados", "id": garantia.id, "cliente": garantia.cliente, "cedula": garantia.cedula, "telefono": garantia.telefono, "email": garantia.email}

# REASIGNAR USUARIO
@app.put("/api/garantias/{gid}/asignar")
def reasignar_usuario(gid: int, usuario_asignado: str = Form(...), token: str = Header(None), db: Session = Depends(get_db)):
    username = verify_token(token)
    dbuser = db.query(Usuario).filter(Usuario.username == username).first()
    if not dbuser:
        raise HTTPException(status_code=401, detail="Usuario inválido")

    garantia = db.query(Garantia).filter(Garantia.id == gid).first()
    if not garantia:
        raise HTTPException(status_code=404, detail="Garantía no encontrada")
    
    # Verificar que el usuario exista
    usuario = db.query(Usuario).filter(Usuario.username == usuario_asignado).first()
    if not usuario:
        raise HTTPException(status_code=400, detail="Usuario no existe")
    
    # Permisos: admin puede reasignar cualquier garantía; técnico solo puede reasignar si la garantía está asignada a él
    if dbuser.rol not in ["admin", "tecnico"]:
        raise HTTPException(status_code=403, detail="No tiene permiso para reasignar garantías")
    if dbuser.rol == "tecnico" and garantia.usuario_asignado != username:
        raise HTTPException(status_code=403, detail="Solo puede reasignar garantías que estén asignadas a usted")

    garantia.usuario_asignado = usuario_asignado
    db.commit()
    return {"mensaje": "Usuario asignado exitosamente", "usuario_asignado": usuario_asignado}

# RECIBO DE GARANTÍA
@app.get("/api/garantias/{gid}/recibo")
def generar_recibo(gid: int, token: str = Header(None), db: Session = Depends(get_db)):
    import os
    
    username = verify_token(token)
    
    garantia = db.query(Garantia).filter(Garantia.id == gid).first()
    if not garantia:
        raise HTTPException(status_code=404, detail="Garantía no encontrada")
    
    config = db.query(ConfiguracionEmpresa).first()
    if not config:
        config = ConfiguracionEmpresa()
    
    # Leer plantilla HTML
    html_path = os.path.join(os.path.dirname(__file__), "static", "adjunto.html")
    try:
        with open(html_path, 'r', encoding='utf-8') as f:
            html_template = f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Plantilla HTML no encontrada")
    
    # Preparar datos
    fecha_registro = garantia.fecha_registro.strftime('%d/%m/%Y') if garantia.fecha_registro else ''
    hora_registro = garantia.fecha_registro.strftime('%H:%M:%S') if garantia.fecha_registro else ''
    producto = " ".join([p for p in [garantia.tipo_producto, garantia.marca, garantia.modelo] if p])
    
    # Reemplazos con variables {{}}
    reemplazos = {
        '{{numero_recibo}}': str(garantia.id),
        '{{telefono}}': config.telefono or '',
        '{{email}}': config.email or '',
        '{{direccion}}': config.direccion or '',
        '{{nit}}': config.nit or '',
        '{{nombre_empresa}}': config.nombre_empresa or 'JD Soluciones',
        '{{fecha}}': fecha_registro,
        '{{hora}}': hora_registro,
        '{{cliente}}': garantia.cliente or '',
        '{{telefono_cliente}}': garantia.telefono or '',
        '{{usuario}}': username or '',
        '{{estado}}': garantia.estado or 'Recibido',
        '{{producto}}': producto or 'Producto',
        '{{fallo}}': garantia.descripcion_falla or '',
    }
    
    # Aplicar reemplazos
    html_procesado = html_template
    for placeholder, valor in reemplazos.items():
        html_procesado = html_procesado.replace(placeholder, str(valor))
    
    # Devolver HTML directamente
    return Response(
        content=html_procesado,
        media_type='text/html'
    )
