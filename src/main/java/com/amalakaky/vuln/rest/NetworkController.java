package com.amalakaky.vuln.rest;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;

@RestController
public class NetworkController {

    @PostMapping("/api/network/ping")
    public String ping(@RequestParam String ip) {
        StringBuilder output = new StringBuilder();

        try {
            // Intentionally vulnerable command construction (CWE-78)
            Process process = Runtime.getRuntime().exec("ping -c 4 " + ip);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            process.waitFor();
        } catch (Exception e) {
            output.append("Error: ").append(e.getMessage());
        }

        return output.toString();
    }
}

