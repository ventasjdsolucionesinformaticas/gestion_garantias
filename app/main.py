import os, uuid, shutil
from fastapi import FastAPI, UploadFile, File, Form, Header, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import Garantia, Comentario, Usuario
from pydantic import BaseModel
from typing import Optional
from security import create_token, verify_token
from sqlalchemy.exc import IntegrityError
import pandas as pd
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

init_admin()

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

# GARANTIAS
@app.post("/api/garantias")
async def crear_garantia_api(
    cliente: str = Form(...),
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
    nueva = Garantia(cliente=cliente, producto=producto, factura=factura, fecha_compra=fecha_compra, descripcion_falla=descripcion_falla, imagen_path=imagen_path, estado="Pendiente")
    db.add(nueva)
    db.commit()
    db.refresh(nueva)
    return {"id": nueva.id, "cliente": nueva.cliente, "producto": nueva.producto, "estado": nueva.estado, "fecha_registro": nueva.fecha_registro.isoformat()}

@app.get("/api/garantias")
def listar_garantias_api(db: Session = Depends(get_db), token: str = Header(None)):
    verify_token(token)
    items = db.query(Garantia).order_by(Garantia.id.desc()).all()
    out = []
    for g in items:
        out.append({"id": g.id, "cliente": g.cliente, "producto": g.producto, "factura": g.factura, "fecha_compra": g.fecha_compra, "descripcion_falla": g.descripcion_falla, "imagen_path": g.imagen_path, "estado": g.estado, "fecha_registro": g.fecha_registro.isoformat()})
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
    items = db.query(Garantia).order_by(Garantia.id.desc()).all()
    rows = []
    for g in items:
        rows.append({"id": g.id, "cliente": g.cliente, "producto": g.producto, "factura": g.factura, "fecha_compra": g.fecha_compra, "descripcion_falla": g.descripcion_falla, "estado": g.estado, "fecha_registro": g.fecha_registro.isoformat()})
    df = pd.DataFrame(rows)
    out_path = os.path.join("data", f"garantias_export_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.xlsx")
    df.to_excel(out_path, index=False)
    return FileResponse(out_path, filename=os.path.basename(out_path), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
