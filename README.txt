Garantías JD Soluciones - v3.4
Instrucciones rápidas (Windows + Docker Desktop o Linux):

1. Descomprimir el ZIP en una carpeta, por ejemplo C:\proyectos\garantias-app-v3.4
2. Abrir terminal en esa carpeta.
3. Levantar la aplicación:
   docker compose up -d --build
4. Ver logs:
   docker logs -f garantias_app_v3_4
5. Acceder en el navegador:
   http://localhost:8000
   Swagger: http://localhost:8000/docs
   Usuario: admin
   Contraseña: admin123

Persistencia:
- La base SQLite se crea en ./data/garantias.db
- Las imágenes y adjuntos se guardan en ./app/uploads/

Para detener:
   docker compose down

Notas:
- El header esperado para pasar el token es 'token: <valor>'
- Si falta o es inválido, la API devuelve 401 (no 500)
- Cambia SECRET_KEY en app/security.py por una clave segura antes de producción.
