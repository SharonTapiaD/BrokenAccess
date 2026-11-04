# Práctica: OWASP A01:2025 – Pérdida de Control de Acceso (Broken Access Control)

**Duración:** 45 min · **Entorno:** Kali Linux (VM) · **Herramientas:** Python 3, Flask, Burp Suite Community, curl

## Archivos
| Archivo | Para qué sirve |
|---|---|
| `app_vulnerable.py` | App insegura (3 fallas) |
| `app_segura.py` | Misma app corregida |
| `pruebas.sh` | Pruebas automáticas con curl (antes/después) |

## Cronograma sugerido
| Min | Paso |
|---|---|
| 0–5 | Preparar entorno |
| 5–10 | Levantar app vulnerable y explorarla |
| 10–30 | Pentest + explotación con Burp (3 ataques) |
| 30–40 | Aplicar corrección (app_segura.py) |
| 40–45 | Re-test y conclusiones |

---
## 1. Preparación (5 min)
```bash
cd ~/lab_bac
sudo apt update && sudo apt install -y python3-flask
chmod +x pruebas.sh
```
Si `python3-flask` no está disponible: `python3 -m venv venv && source venv/bin/activate && pip install flask`

## 2. Levantar la app vulnerable
```bash
python3 app_vulnerable.py
```
Abrir **Burp Suite** → *Proxy* → *Intercept is off* → **Open browser** (Chromium integrado, ya viene con proxy configurado).
Entrar a `http://127.0.0.1:5000` con `alice / alice123`. Navegar: Dashboard → Mi perfil.
En Burp: *Proxy → HTTP history* para ver las peticiones.

## 3. Pruebas de penetración y explotación

### Ataque 1 – IDOR (referencia directa insegura a objetos)
1. Logueado como **alice**, abrir "Mi perfil": `GET /perfil?id=2`.
2. En *HTTP history* clic derecho a esa petición → **Send to Repeater**.
3. En Repeater cambiar `id=2` por `id=1` y `id=3` → **Send**.
4. **Resultado:** se ve el dato confidencial del admin (tarjeta) y de bob (salario). ✅ Vulnerable.

### Ataque 2 – Elevación de privilegios por manipulación de cookie
1. Con alice, intentar abrir `http://127.0.0.1:5000/admin` → **403** (parece protegido).
2. Enviar esa petición a Repeater. Modificar el header:
   `Cookie: uid=2; role=user` → `Cookie: uid=2; role=admin`
3. **Send.** **Resultado:** 200 y se muestra el panel con usuarios y **contraseñas**. ✅ Vulnerable.

### Ataque 3 – Navegación forzada (forced browsing)
1. Sin iniciar sesión (o con curl), pedir:
```bash
curl http://127.0.0.1:5000/api/usuarios
```
2. **Resultado:** JSON con todos los usuarios y claves. ✅ Vulnerable.
   (Opcional: en Burp **Intruder** o con `gobuster dir -u http://127.0.0.1:5000 -w /usr/share/wordlists/dirb/common.txt` para *descubrir* rutas como `/admin` y `/api`.)

### Evidencia automática
```bash
./pruebas.sh
```
Debe mostrar **HTTP 200 en las 3 pruebas** (guardar captura para el reporte).

## 4. Análisis de causas (para explicar al grupo)
| Falla | Causa raíz | Relación con el texto OWASP |
|---|---|---|
| IDOR | No se valida que el recurso pertenezca al usuario | "Permitir ver o editar la cuenta de otra persona proporcionando su identificador" |
| Cookie `role` | El servidor confía en datos que controla el cliente | "Manipulación de metadatos… cookie manipulada para elevar privilegios" |
| `/api/usuarios` | No hay control de acceso en el endpoint | "Navegación forzada" y "violación de denegar por defecto" |

## 5. Corrección (10 min)
Detener la app vulnerable (Ctrl+C) y ejecutar la corregida:
```bash
python3 app_segura.py
```
Mostrar al grupo con `diff app_vulnerable.py app_segura.py` o abriendo ambos archivos. Cambios clave:

1. **Sesión firmada** (`session` de Flask + `secret_key`) en lugar de cookies planas `uid`/`role`.
2. **El rol se lee de la base de datos** en cada petición, nunca del cliente.
3. **Decoradores `@login_required` y `@admin_required`** centralizados → *denegar por defecto*.
4. **Verificación de propiedad** en `/perfil`: si `id != usuario_en_sesión` y no es admin → **403**.
5. **`/api/usuarios` protegido** y sin exponer contraseñas ni datos sensibles (mínimo privilegio).
6. **Registro de fallas** de acceso en `accesos.log`.
7. Contraseñas con **hash** (`generate_password_hash`), cookies `HttpOnly` y `SameSite`.

## 6. Re-test
Con la app segura corriendo:
```bash
./pruebas.sh
```
Esperado: **302 / 403** en las 3 pruebas. Repetir manualmente en Burp:
- Repeater con `id=1` como alice → **403**.
- Cookie `role=admin` inventada → **302** (no hay sesión válida).
- `curl /api/usuarios` → **302** (redirige al login).

Ver bitácora: `cat accesos.log` (mostrar los intentos bloqueados).

## 7. Estructura del reporte
1. Portada, objetivo y alcance
2. Descripción de A01:2025 (usar el texto de OWASP)
3. Entorno (Kali, versiones de Python/Flask/Burp)
4. Código vulnerable (fragmentos comentados)
5. Pruebas de penetración (capturas de Burp y de `pruebas.sh`)
6. Explotación (impacto: robo de datos, escalamiento)
7. Correcciones aplicadas (tabla antes/después)
8. Re-test y resultados
9. Conclusiones y referencias (OWASP Top 10:2025)

> **Aviso:** estas apps son solo para laboratorio en localhost. Nunca ejecutar estas técnicas contra sistemas sin autorización.
