package com.cybersecurity.config;

import com.cybersecurity.exception.InvalidConfigurationException;
import com.cybersecurity.model.PermissionsConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.InputStream;

@Configuration
public class PermissionConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(PermissionConfiguration.class);
    private static final String PERMISSIONS_FILE = "permissions.json";

    @Bean
    public PermissionsConfig permissionsConfig(ObjectMapper objectMapper) {
        logger.info("Loading permissions configuration from {}", PERMISSIONS_FILE);
        try {
            Resource resource = new ClassPathResource(PERMISSIONS_FILE);
            if (!resource.exists()) {
                throw new InvalidConfigurationException("Configuration file '" + PERMISSIONS_FILE + "' not found in classpath.");
            }

            try (InputStream inputStream = resource.getInputStream()) {
                PermissionsConfig config = objectMapper.readValue(inputStream, PermissionsConfig.class);
                validatePermissionsConfig(config);
                logger.info("Successfully loaded permissions.json: {} permissions defined.",
                        config.getPermissions().size());
                return config;
            }
        } catch (InvalidConfigurationException ice) {
            logger.error("Permissions configuration validation failure: {}", ice.getMessage());
            throw ice;
        } catch (Exception e) {
            logger.error("Failed to load or parse permissions configuration: {}", e.getMessage(), e);
            throw new InvalidConfigurationException("Error parsing '" + PERMISSIONS_FILE + "': " + e.getMessage(), e);
        }
    }

    private void validatePermissionsConfig(PermissionsConfig config) {
        if (config == null) {
            throw new InvalidConfigurationException("Permissions configuration cannot be null.");
        }
        if (config.getPermissions() == null || config.getPermissions().isEmpty()) {
            throw new InvalidConfigurationException("Permissions list is missing or empty in permissions.json.");
        }
        if (config.getDefaultUnknownPermission() == null) {
            throw new InvalidConfigurationException("Default unknown permission fallback is missing in permissions.json.");
        }
        if (config.getMandatoryWarning() == null || config.getMandatoryWarning().isBlank()) {
            throw new InvalidConfigurationException("Mandatory warning text is missing in permissions.json.");
        }
    }
}
