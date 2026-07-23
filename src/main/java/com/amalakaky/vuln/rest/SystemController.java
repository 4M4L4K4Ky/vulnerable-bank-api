package com.amalakaky.vuln.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.nio.file.Files;

@RestController
public class SystemController {

    private static final String BASE_DIR = "files/";

    @GetMapping("/api/system/download")
    public String downloadFile(@RequestParam String filename) {
        try {
            // Intentionally vulnerable path concatenation (CWE-22)
            File file = new File(BASE_DIR + filename);
            return Files.readString(file.toPath());
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

