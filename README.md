# Vulnerable app — Laboratorio 04 FDSI (fase SAST)

Aplicación **deliberadamente vulnerable** creada para el ejercicio de Static
Application Security Testing (SAST) del Laboratorio 04. Contiene fallos plantados
a propósito para que una herramienta SAST (Snyk) los detecte y podamos triarlos y
remediarlos.

## Cómo ejecutar (opcional)

```bash
mvn clean package
java -jar target/vulnerable-app.jar
# http://localhost:8080/login?user=admin&pass=admin123
# http://localhost:8080/ping?host=127.0.0.1
# http://localhost:8080/file?name=index.txt
```

## Fallos plantados (baseline `v0-vulnerable`)

| # | Fallo | CWE | OWASP Top 10 | Archivo:línea |
|---|-------|-----|--------------|---------------|
| VULN-01 | SQL Injection (consulta por concatenación) | CWE-89 | A03:2021 – Injection | `App.java:73` |
| VULN-02 | Command Injection (`Runtime.exec` con input) | CWE-78 | A03:2021 – Injection | `App.java:92` |
| VULN-03 | Secreto hardcodeado (API key en el código) | CWE-798 | A07:2021 – Identification & Auth Failures | `App.java:33` |
| VULN-04 | Hashing débil (MD5 para contraseñas) | CWE-327 | A02:2021 – Cryptographic Failures | `App.java:68` |
| VULN-05 | Dependencia con CVE (Log4j 2.14.1 / Log4Shell) | CWE-1035 | A06:2021 – Vulnerable & Outdated Components | `pom.xml:25` |
| VULN-06 | Path Traversal (lectura de archivos sin validar) | CWE-22 | A01:2021 – Broken Access Control | `App.java:107` |

*(Las líneas apuntan a la sentencia vulnerable; el comentario `[VULN-0X]` la precede.)*

## Detalle de cada fallo

- **VULN-01 · SQLi** — `handleLogin` construye la consulta concatenando `user`
  directamente. Un `user` como `admin' -- ` evade la autenticación.
- **VULN-02 · Command Injection** — `handlePing` pasa `host` a `Runtime.exec`.
  `?host=127.0.0.1;id` ejecuta comandos arbitrarios.
- **VULN-03 · Secreto hardcodeado** — `API_KEY` vive en el código (y se registra en
  el log al arrancar, agravándolo).
- **VULN-04 · MD5** — `md5()` usa un algoritmo roto para contraseñas; sin sal y
  rápido de crackear.
- **VULN-05 · Dependencia vulnerable** — `log4j-core 2.14.1` (Log4Shell,
  CVE-2021-44228, Critical) fijado en `pom.xml`.
- **VULN-06 · Path Traversal** — `handleFile` concatena `name` a la ruta sin
  validar; `?name=../../etc/passwd` escapa del directorio `files/`.
