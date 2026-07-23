package com.amalakaky.vuln.rest;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

@RestController
public class CryptoController {

    @PostMapping("/api/crypto/hash")
    public Map<String, String> hashPassword(@RequestParam String password) {
        Map<String, String> response = new HashMap<>();

        try {
            // Intentionally weak hash algorithm and no salt (CWE-327)
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hashedBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));

            StringBuilder hex = new StringBuilder();
            for (byte b : hashedBytes) {
                hex.append(String.format("%02x", b));
            }

            response.put("algorithm", "MD5");
            response.put("hash", hex.toString());
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }

        return response;
    }
}

