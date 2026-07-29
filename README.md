# vulnerable-bank-api

[![Java](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3-6DB33F?logo=springboot)](https://spring.io/projects/spring-boot)
[![Maven](https://img.shields.io/badge/Maven-C71A36?logo=apachemaven)](https://maven.apache.org/)
[![OWASP Top 10](https://img.shields.io/badge/OWASP_Top_10-2025-000000?logo=owasp)](https://owasp.org/Top10/2025/en/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![CWE Coverage](https://img.shields.io/badge/CWEs-22%20implementadas-blueviolet)](#vulnerabilidades-implementadas)

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

* Identificar vulnerabilidades **OWASP Top 10 (2025)** en codigo realista
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
graph TD
    A[Cliente HTTP] --> B[Spring Boot 3]
    B --> C[UserController]
    B --> D[CryptoController]
    B --> E[SystemController]
    B --> F[NetworkController]
    B --> G[BadPracticesController]
    B --> H[OwaspController]
    C --> I[(MySQL / JDBC Statement)]
    F --> J[Runtime.exec]
    H --> K[13 endpoints OWASP Top 10]
