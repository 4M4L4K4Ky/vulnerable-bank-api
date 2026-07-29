package com.amalakaky.vuln.rest;

import jakarta.xml.parsers.DocumentBuilder;
import jakarta.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@RestController
public class OwaspController {

    private static final Logger LOG = Logger.getLogger(OwaspController.class.getName());

    // ============================================================
    // CWE-79: Reflected XSS (A03: Injection) — Severity: 7 (MEDIUM)
    // Devuelve el input del usuario directamente en la respuesta HTML
    // sin escapar, permitiendo inyección de scripts.
    // ============================================================
    @GetMapping("/api/owasp/xss/reflect")
    public String xssReflect(@RequestParam String q) {
        return "<html><body><h1>Resultado de busqueda</h1><p>" + q + "</p></body></html>";
    }

    // ============================================================
    // CWE-79: Stored XSS (A03: Injection) — Severity: 7 (MEDIUM)
    // Almacena comentarios sin sanitizar y los devuelve sin escapar.
    // ============================================================
    private static final java.util.List<String> comments = new java.util.ArrayList<>();

    @PostMapping("/api/owasp/xss/comment")
    public Map<String, String> postComment(@RequestBody Map<String, String> body) {
        String comment = body.get("comment");
        comments.add(comment);
        Map<String, String> resp = new HashMap<>();
        resp.put("status", "ok");
        resp.put("comment", comment);
        return resp;
    }

    @GetMapping("/api/owasp/xss/comments")
    public String getComments() {
        StringBuilder html = new StringBuilder("<html><body><h1>Comentarios</h1><ul>");
        for (String c : comments) {
            html.append("<li>").append(c).append("</li>");
        }
        html.append("</ul></body></html>");
        return html.toString();
    }

    // ============================================================
    // CWE-352: CSRF (A01: Broken Access Control) — Severity: 6 (MEDIUM)
    // Endpoint POST sin token CSRF ni verificación de origen.
    // Cualquier sitio externo puede hacer peticiones en nombre del usuario.
    // ============================================================
    @PostMapping("/api/owasp/csrf/change-email")
    public Map<String, String> changeEmail(@RequestParam String email) {
        Map<String, String> resp = new HashMap<>();
        resp.put("status", "Email cambiado a " + email);
        return resp;
    }

    // ============================================================
    // CWE-862: Missing Authorization (A01: Broken Access Control) — Severity: 6 (MEDIUM)
    // Endpoint de administración sin verificación de rol.
    // Cualquier usuario puede ejecutar acciones de admin.
    // ============================================================
    @PostMapping("/api/owasp/admin/delete-all")
    public Map<String, String> deleteAllUsers(@RequestParam(defaultValue = "true") String confirm) {
        Map<String, String> resp = new HashMap<>();
        resp.put("action", "DELETE_ALL_USERS");
        resp.put("status", confirm.equals("true") ? "Todos los usuarios eliminados" : "Cancelado");
        return resp;
    }

    // ============================================================
    // CWE-200: Information Exposure (A01: Broken Access Control) — Severity: 4 (LOW)
    // Expone configuración interna del servidor y variables de entorno.
    // ============================================================
    @GetMapping("/api/owasp/debug/env")
    public Map<String, String> debugEnv() {
        Map<String, String> env = new HashMap<>();
        env.put("java.version", System.getProperty("java.version"));
        env.put("os.name", System.getProperty("os.name"));
        env.put("user.dir", System.getProperty("user.dir"));
        env.put("java.class.path", System.getProperty("java.class.path"));
        env.put("db.url", System.getenv("DB_URL") != null ? System.getenv("DB_URL") : "not-set");
        env.put("db.password", System.getenv("DB_PASSWORD") != null ? System.getenv("DB_PASSWORD") : "not-set");
        return env;
    }

    // ============================================================
    // CWE-532: Information Exposure via Logs (A09: Logging Failures) — Severity: 3 (LOW)
    // Las contraseñas quedan registradas en texto plano en los logs.
    // ============================================================
    @PostMapping("/api/owasp/login")
    public Map<String, String> login(@RequestParam String username, @RequestParam String password) {
        LOG.info("Intento de login - usuario: " + username + ", password: " + password);
        Map<String, String> resp = new HashMap<>();
        resp.put("message", "Login attempted");
        return resp;
    }

    // ============================================================
    // CWE-918: Server-Side Request Forgery — SSRF (A10: SSRF) — Severity: 7 (MEDIUM)
    // El servidor hace peticiones HTTP a URLs proporcionadas por el usuario
    // sin validar, permitiendo acceso a recursos internos.
    // ============================================================
    @GetMapping("/api/owasp/ssrf/fetch")
    public String ssrfFetch(@RequestParam String url) {
        try {
            URL target = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) target.openConnection();
            conn.setConnectTimeout(5000);
            conn.setRequestMethod("GET");
            byte[] response = conn.getInputStream().readAllBytes();
            return new String(response, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ============================================================
    // CWE-502: Unsafe Deserialization (A08: Integrity Failures) — Severity: 8 (HIGH)
    // Deserializa objetos Java directamente desde datos proporcionados
    // por el usuario, permitiendo ejecución remota de código (RCE).
    // ============================================================
    @PostMapping("/api/owasp/deserialize")
    public String unsafeDeserialize(@RequestBody String base64Data) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();
            ois.close();
            return "Objeto deserializado: " + obj.getClass().getName();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ============================================================
    // CWE-434: Unrestricted File Upload (A01: Broken Access Control) — Severity: 7 (MEDIUM)
    // Permite subir cualquier tipo de archivo sin validar extensión
    // ni contenido, potencialmente permitiendo subida de shells.
    // ============================================================
    @PostMapping("/api/owasp/upload")
    public Map<String, String> uploadFile(@RequestParam String filename, @RequestBody byte[] content) {
        Map<String, String> resp = new HashMap<>();
        try {
            File uploadDir = new File("uploads");
            if (!uploadDir.exists()) uploadDir.mkdirs();
            File output = new File("uploads/" + filename);
            try (FileOutputStream fos = new FileOutputStream(output)) {
                fos.write(content);
            }
            resp.put("status", "Archivo guardado en: " + output.getAbsolutePath());
            resp.put("size", String.valueOf(content.length));
        } catch (Exception e) {
            resp.put("error", e.getMessage());
        }
        return resp;
    }

    // ============================================================
    // CWE-611: XML External Entity (XXE) (A05: Security Misconfiguration) — Severity: 7 (MEDIUM)
    // Procesa XML sin deshabilitar entidades externas, permitiendo
    // lectura de archivos internos o SSRF vía DTD personalizado.
    // ============================================================
    @PostMapping("/api/owasp/xxe/parse")
    public String parseXml(@RequestBody String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            return "Documento XML parseado: " + doc.getDocumentElement().getNodeName();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ============================================================
    // CWE-400: Uncontrolled Resource Consumption (A04: Insecure Design) — Severity: 4 (LOW)
    // Acepta contenido ilimitado sin rate limiting ni validación de tamaño,
    // permitiendo agotar la memoria del servidor.
    // ============================================================
    @PostMapping("/api/owasp/echo")
    public String echo(@RequestBody String content) {
        return "Recibido: " + content.length() + " bytes";
    }

    // ============================================================
    // CWE-287: Improper Authentication (A07: Identification Failures) — Severity: 6 (MEDIUM)
    // Endpoint sensible que acepta un simple token hardcodeado
    // como "autenticación", sin verificación real.
    // ============================================================
    @PostMapping("/api/owasp/reset-password")
    public Map<String, String> resetPassword(@RequestParam String userId,
                                              @RequestParam(defaultValue = "reset123") String newPassword,
                                              @RequestParam(defaultValue = "admin") String authToken) {
        Map<String, String> resp = new HashMap<>();
        if ("admin".equals(authToken) || "root".equals(authToken)) {
            resp.put("status", "Password reset para usuario " + userId);
            resp.put("newPassword", newPassword);
        } else {
            resp.put("status", "Token invalido");
        }
        return resp;
    }

    // ============================================================
    // CWE-312: Cleartext Storage of Sensitive Data (A02: Cryptographic Failures) — Severity: 5 (MEDIUM)
    // Almacena números de tarjetas de crédito en texto plano en memoria.
    // ============================================================
    private static final java.util.List<Map<String, String>> creditCards = new java.util.ArrayList<>();

    @PostMapping("/api/owasp/payment/save-card")
    public Map<String, String> saveCard(@RequestBody Map<String, String> cardData) {
        Map<String, String> record = new HashMap<>();
        record.put("cardNumber", cardData.get("cardNumber"));
        record.put("cvv", cardData.get("cvv"));
        record.put("holderName", cardData.get("holderName"));
        record.put("expiry", cardData.get("expiry"));
        creditCards.add(record);
        Map<String, String> resp = new HashMap<>();
        resp.put("status", "Tarjeta guardada");
        resp.put("totalCards", String.valueOf(creditCards.size()));
        return resp;
    }

    @GetMapping("/api/owasp/payment/cards")
    public java.util.List<Map<String, String>> getCards() {
        return creditCards;
    }

    // ============================================================
    // CWE-601: Open Redirect (A01: Broken Access Control) — Severity: 4 (LOW)
    // Redirige al usuario a cualquier URL externa sin validación.
    // ============================================================
    @GetMapping("/api/owasp/redirect")
    public String openRedirect(@RequestParam String url) {
        return "<html><head><meta http-equiv='refresh' content='0; url=" + url + "'></head>" +
               "<body><a href='" + url + "'>Redirigiendo...</a></body></html>";
    }

    // ============================================================
    // CWE-326: Inadequate Encryption Strength (A02: Cryptographic Failures) — Severity: 5 (MEDIUM)
    // Usa un cifrado débil (DES) para "proteger" datos sensibles.
    // ============================================================
    @PostMapping("/api/owasp/crypto/weak-encrypt")
    public Map<String, String> weakEncrypt(@RequestParam String data) {
        Map<String, String> resp = new HashMap<>();
        try {
            javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance("DES");
            keyGen.init(56);
            javax.crypto.SecretKey key = keyGen.generateKey();
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            resp.put("algorithm", "DES/ECB");
            resp.put("encrypted", Base64.getEncoder().encodeToString(encrypted));
        } catch (Exception e) {
            resp.put("error", e.getMessage());
        }
        return resp;
    }

    // ============================================================
    // CWE-209: Information Exposure Through Error Messages (A05: Security Misconfiguration)
    // Severity: 1 (INFO)
    // Las trazas de error internas (rutas de archivos, stacks internos)
    // se devuelven al usuario, filtrando información del servidor.
    // ============================================================
    @GetMapping("/api/owasp/debug/error-details")
    public Map<String, String> errorDetails(@RequestParam(defaultValue = "/etc/passwd") String filepath) {
        Map<String, String> resp = new HashMap<>();
        try {
            java.nio.file.Files.readString(java.nio.file.Path.of(filepath));
        } catch (Exception e) {
            resp.put("error", "No se pudo leer: " + filepath);
            resp.put("internalPath", e.getStackTrace()[0].toString());
            resp.put("exceptionType", e.getClass().getName());
        }
        return resp;
    }

    // ============================================================
    // CWE-117: Improper Output Neutralization for Logs (A09: Logging Failures)
    // Severity: 1 (INFO)
    // Permite inyectar entradas falsas en los logs del servidor ya que
    // el input del usuario se incluye sin sanitizar en las trazas.
    // ============================================================
    @PostMapping("/api/owasp/log/inject")
    public Map<String, String> logInject(@RequestParam String message) {
        LOG.info("[AUDIT] Accion realizada por usuario: " + message);
        Map<String, String> resp = new HashMap<>();
        resp.put("logged", message);
        return resp;
    }

    // ============================================================
    // CWE-547: Use of Hard-coded, Security-relevant Constants (A05: Security Misconfiguration)
    // Severity: 1 (INFO)
    // Constantes de seguridad hardcodeadas que deberían ser configurables.
    // ============================================================
    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final int SESSION_TIMEOUT_MINUTES = 30;
    private static final String DEFAULT_ADMIN_PASSWORD = "admin";
    private static final String API_VERSION = "1.0";
    private static final int TOKEN_LENGTH = 6;

    @GetMapping("/api/owasp/debug/security-config")
    public Map<String, Object> securityConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("maxLoginAttempts", MAX_LOGIN_ATTEMPTS);
        config.put("sessionTimeoutMinutes", SESSION_TIMEOUT_MINUTES);
        config.put("defaultAdminPassword", DEFAULT_ADMIN_PASSWORD);
        config.put("apiVersion", API_VERSION);
        config.put("tokenLength", TOKEN_LENGTH);
        config.put("algorithm", "DES");
        config.put("hashType", "MD5");
        config.put("salt", "static-salt-value");
        return config;
    }

    // ============================================================
    // CWE-1104: Use of Unmaintained Third-Party Components (A06: Vulnerable Components)
    // Severity: 1 (INFO)
    // Expone versiones de dependencias con vulnerabilidades conocidas.
    // ============================================================
    @GetMapping("/api/owasp/debug/dependencies")
    public Map<String, String> dependencies() {
        Map<String, String> deps = new HashMap<>();
        deps.put("spring-boot", "3.3.2");
        deps.put("mysql-connector", "unknown (runtime)");
        deps.put("java-version", System.getProperty("java.version"));
        deps.put("known-vulnerabilities", "CVE-2024-xxxxx (no actualizado)");
        deps.put("log4j", "2.x (no parcheado)");
        return deps;
    }
}
