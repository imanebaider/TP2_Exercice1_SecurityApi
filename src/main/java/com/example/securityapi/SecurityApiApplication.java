package com.example.securityapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan  // pour trouver RsaKeys
public class SecurityApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecurityApiApplication.class, args);
    }
}
