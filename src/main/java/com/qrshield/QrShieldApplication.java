package com.qrshield;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class QrShieldApplication {
    public static void main(String[] args) throws IOException {
        Files.createDirectories(Path.of("instance")); // SQLite needs the folder to exist
        SpringApplication.run(QrShieldApplication.class, args);
    }
}
