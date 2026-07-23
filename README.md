# vulnerable-bank-api

Microservicio REST construido con **Java 21**, **Spring Boot 3** y **Maven**, diseñado de forma deliberada para incluir vulnerabilidades críticas y malas prácticas de desarrollo.

> [!WARNING]
> Este proyecto es **intencionalmente inseguro** y se usa solo con fines formativos (laboratorios, análisis estático/dinámico y prácticas de pentesting en entorno controlado).

## Objetivo académico

Este repositorio sirve como base para:

- identificar vulnerabilidades OWASP Top 10 en código realista,
- practicar explotación controlada y validación de hallazgos,
- documentar impacto, riesgo y recomendaciones de mitigación.

## Stack técnico

- Java 21
- Spring Boot 3 (solo `spring-boot-starter-web`)
- Maven
- JDBC directo con MySQL (`mysql-connector-j`)

## Decisiones intencionales (inseguras)

- No se incluye Spring Security.
- No se aplica validación de entradas.
- No se usa JPA/Hibernate (acceso con JDBC en crudo).
- Se incorporan vulnerabilidades críticas de forma explícita.

## Estructura principal

- `src/main/java/com/amalakaky/vuln/VulnerableBankApiApplication.java`
- `src/main/java/com/amalakaky/vuln/rest/UserController.java`
- `src/main/java/com/amalakaky/vuln/rest/CryptoController.java`
- `src/main/java/com/amalakaky/vuln/rest/SystemController.java`
- `src/main/java/com/amalakaky/vuln/rest/NetworkController.java`
- `src/main/java/com/amalakaky/vuln/rest/BadPracticesController.java`

## Vulnerabilidades implementadas

| Endpoint | Vulnerabilidad | CWE |
|---|---|---|
| `GET /api/users/balance?username=...` | Credenciales hardcodeadas + SQL Injection por concatenación en `Statement` | CWE-798, CWE-89 |
| `POST /api/crypto/hash?password=...` | Hash inseguro con MD5 sin salt | CWE-327 |
| `GET /api/system/download?filename=...` | Path Traversal por concatenación directa de ruta | CWE-22 |
| `POST /api/network/ping?ip=...` | OS Command Injection en `Runtime.exec(...)` | CWE-78 |
| `GET /api/system/risk-score?...` | Clase con múltiples malas prácticas de mantenibilidad y robustez | N/A |

## Clase de malas prácticas

`BadPracticesController` incluye anti-patrones comunes de forma intencional:

- demasiados `if` encadenados,
- múltiples `return` tempranos,
- uso extensivo de números mágicos,
- estado global mutable (`globalCounter`),
- captura genérica de excepciones sin tratamiento adecuado.

## Ejecución local

```bash
cd "C:\Users\skull\IdeaProjects\vulnerable-bank-api"
mvn spring-boot:run
```

La aplicación arranca por defecto en `http://localhost:8080`.

## Ejemplos rápidos de uso

```bash
curl "http://localhost:8080/api/users/balance?username=alice"
curl -X POST "http://localhost:8080/api/crypto/hash?password=123456"
curl "http://localhost:8080/api/system/download?filename=notes.txt"
curl -X POST "http://localhost:8080/api/network/ping?ip=127.0.0.1"
curl "http://localhost:8080/api/system/risk-score?userType=basic&amount=6000&age=45&failedLogins=4&country=ES&admin=false&notes=test"
```

## Aviso final

Proyecto orientado a **docencia en ciberseguridad**. No desplegar en producción ni reutilizar este código como base de sistemas reales.
