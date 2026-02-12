"""
Script para borrar datos de prueba en producción.
- Borra TODAS las garantías y sus comentarios.
- Borra los archivos en uploads/ (imágenes de garantías y adjuntos), excepto el logo de la empresa.
- NO borra: usuarios, configuración de empresa.

Cómo ejecutar:

  Si usas Docker:
    docker exec -it garantias_app_v3_4 python limpiar_datos_prueba.py

  Si corres la app localmente desde la carpeta app/:
    cd app
    python limpiar_datos_prueba.py

  Si corres desde la raíz del proyecto:
    cd app && python limpiar_datos_prueba.py
"""
import os
import sys

# Ir a la carpeta app para que la BD (./data/garantias.db) y uploads coincidan con la app
app_dir = os.path.dirname(os.path.abspath(__file__))
if os.getcwd() != app_dir:
    os.chdir(app_dir)
sys.path.insert(0, app_dir)

from database import SessionLocal
from models import Garantia, Comentario, ConfiguracionEmpresa

def main():
    db = SessionLocal()
    try:
        # Contar antes
        n_garantias = db.query(Garantia).count()
        n_comentarios = db.query(Comentario).count()

        # Logo a conservar (si existe)
        config = db.query(ConfiguracionEmpresa).first()
        logo_path = None
        logo_filename = None
        if config and config.logo_path:
            # logo_path es tipo "/uploads/abc123.png"
            logo_path = config.logo_path
            if logo_path.startswith("/uploads/"):
                logo_filename = logo_path.replace("/uploads/", "")

        # Borrar todas las garantías (los comentarios se borran por cascade)
        db.query(Garantia).delete()
        db.commit()

        # Limpiar carpeta uploads (excepto logo)
        uploads_dir = os.path.join(os.getcwd(), "uploads")
        deleted_files = 0
        if os.path.isdir(uploads_dir):
            for name in os.listdir(uploads_dir):
                if logo_path and name == logo_filename:
                    continue
                path = os.path.join(uploads_dir, name)
                if os.path.isfile(path):
                    try:
                        os.remove(path)
                        deleted_files += 1
                    except Exception as e:
                        print(f"  No se pudo borrar {name}: {e}")

        print("Datos de prueba eliminados:")
        print(f"  - Garantías borradas: {n_garantias}")
        print(f"  - Comentarios borrados: {n_comentarios}")
        print(f"  - Archivos en uploads borrados: {deleted_files}")
        if logo_path:
            print(f"  - Logo conservado: {logo_path}")
        print("Usuarios y configuración de empresa se mantienen.")
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    main()
