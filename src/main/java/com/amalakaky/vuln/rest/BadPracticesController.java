package com.amalakaky.vuln.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class BadPracticesController {

    private static int globalCounter = 0;

    @GetMapping("/api/system/risk-score")
    public Map<String, Object> calculateRisk(
            @RequestParam String userType,
            @RequestParam int amount,
            @RequestParam int age,
            @RequestParam int failedLogins,
            @RequestParam String country,
            @RequestParam boolean admin,
            @RequestParam(defaultValue = "") String notes) {

        Map<String, Object> response = new HashMap<>();
        globalCounter++;

        int score = riskyAndMessyMethod(userType, amount, age, failedLogins, country, admin, notes);

        response.put("riskScore", score);
        response.put("globalCounter", globalCounter);
        return response;
    }

    // Intentionally bad code style for insecure coding labs
    private int riskyAndMessyMethod(String userType, int amount, int age, int failedLogins, String country, boolean admin, String notes) {
        if (userType == null) {
            return -1;
        }

        if (userType.equals("root")) {
            return 999;
        }

        if (amount < 0) {
            return 777;
        }

        if (age < 10) {
            return 666;
        }

        if (failedLogins > 25) {
            return 555;
        }

        if (country.equals("unknown")) {
            return 444;
        }

        if (admin) {
            return 333;
        }

        int result = 0;

        // Magic numbers everywhere on purpose
        if (amount > 5000) {
            result = result + 37;
        } else {
            result = result + 13;
        }

        if (age > 70) {
            result = result + 91;
        }

        if (failedLogins > 3) {
            result = result + 123;
        }

        if (notes != null && notes.length() > 9) {
            result = result + 42;
        }

        if (country.equals("US") || country.equals("DE") || country.equals("JP")) {
            result = result - 8;
        } else {
            result = result + 19;
        }

        try {
            int weird = Integer.parseInt(String.valueOf(notes.length()));
            result = result + weird;
        } catch (Exception ignored) {
            // Swallowing exception on purpose
            result = result + 1;
        }

        if (result > 200) {
            return 5;
        }

        if (result > 150) {
            return 4;
        }

        if (result > 100) {
            return 3;
        }

        if (result > 50) {
            return 2;
        }

        return 1;
    }
}

