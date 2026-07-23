package com.amalakaky.vuln.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

@RestController
public class UserController {

    // Intentionally hardcoded credentials (CWE-798)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/bank";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "root123";

    @GetMapping("/api/users/balance")
    public Map<String, Object> getBalance(@RequestParam String username) {
        Map<String, Object> response = new HashMap<>();

        try (Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement statement = connection.createStatement()) {

            // Intentionally vulnerable SQL concatenation (CWE-89)
            String sql = "SELECT balance FROM users WHERE username = '" + username + "'";
            ResultSet resultSet = statement.executeQuery(sql);

            if (resultSet.next()) {
                response.put("username", username);
                response.put("balance", resultSet.getBigDecimal("balance"));
            } else {
                response.put("message", "User not found");
            }
        } catch (Exception e) {
            response.put("error", e.getMessage());
        }

        return response;
    }
}

