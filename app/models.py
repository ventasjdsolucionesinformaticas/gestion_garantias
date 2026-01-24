from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class Garantia(Base):
    __tablename__ = "garantias"
    id = Column(Integer, primary_key=True, index=True)
    cliente = Column(String, index=True, nullable=False)
    cedula = Column(String, nullable=True)
    telefono = Column(String, nullable=True)
    tipo_producto = Column(String, nullable=True)
    marca = Column(String, nullable=True)
    modelo = Column(String, nullable=True)
    serial = Column(String, nullable=True)
    factura = Column(String, nullable=True)
    fecha_compra = Column(String, nullable=True)
    descripcion_falla = Column(Text, nullable=True)
    imagen_path = Column(String, nullable=True)
    estado = Column(String, default="Pendiente")
    fecha_registro = Column(DateTime, default=datetime.utcnow)
    comentarios = relationship("Comentario", back_populates="garantia", cascade="all, delete-orphan")

class Comentario(Base):
    __tablename__ = "comentarios"
    id = Column(Integer, primary_key=True, index=True)
    garantia_id = Column(Integer, ForeignKey("garantias.id"))
    usuario = Column(String, nullable=False)
    texto = Column(Text, nullable=False)
    attachment_path = Column(String, nullable=True)
    fecha = Column(DateTime, default=datetime.utcnow)
    garantia = relationship("Garantia", back_populates="comentarios")

class Usuario(Base):
    __tablename__ = "usuarios"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    rol = Column(String, nullable=False, default="consulta")
    fecha_creacion = Column(DateTime, default=datetime.utcnow)

class ConfiguracionEmpresa(Base):
    __tablename__ = "configuracion_empresa"
    id = Column(Integer, primary_key=True, index=True)
    nombre_empresa = Column(String, nullable=False, default="JD Soluciones")
    telefono = Column(String, nullable=True)
    email = Column(String, nullable=True)
    direccion = Column(Text, nullable=True)
    ciudad = Column(String, nullable=True)
    nit = Column(String, nullable=True)
    logo_path = Column(String, nullable=True)
    fecha_actualizacion = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
