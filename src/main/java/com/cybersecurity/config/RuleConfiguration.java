package com.cybersecurity.config;

import com.cybersecurity.exception.InvalidConfigurationException;
import com.cybersecurity.model.RulesConfig;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.InputStream;

@Configuration
public class RuleConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(RuleConfiguration.class);
    private static final String RULES_FILE = "rules.json";

    @Bean
    public RulesConfig rulesConfig(ObjectMapper objectMapper) {
        logger.info("Loading rules configuration from {}", RULES_FILE);
        try {
            Resource resource = new ClassPathResource(RULES_FILE);
            if (!resource.exists()) {
                throw new InvalidConfigurationException("Configuration file '" + RULES_FILE + "' not found in classpath.");
            }

            try (InputStream inputStream = resource.getInputStream()) {
                RulesConfig config = objectMapper.readValue(inputStream, RulesConfig.class);
                validateRulesConfig(config);
                logger.info("Successfully loaded rules.json: {} message rules, {} URL rules, {} known brands, {} shorteners.",
                        config.getMessageRules().size(),
                        config.getUrlRules().size(),
                        config.getKnownBrands().size(),
                        config.getKnownShorteners().size());
                return config;
            }
        } catch (InvalidConfigurationException ice) {
            logger.error("Rules configuration validation failure: {}", ice.getMessage());
            throw ice;
        } catch (Exception e) {
            logger.error("Failed to load or parse rules configuration: {}", e.getMessage(), e);
            throw new InvalidConfigurationException("Error parsing '" + RULES_FILE + "': " + e.getMessage(), e);
        }
    }

    private void validateRulesConfig(RulesConfig config) {
        if (config == null) {
            throw new InvalidConfigurationException("Rules configuration cannot be null.");
        }
        if (config.getThresholds() == null) {
            throw new InvalidConfigurationException("Thresholds configuration is missing in rules.json.");
        }
        if (config.getMessageRules() == null || config.getMessageRules().isEmpty()) {
            throw new InvalidConfigurationException("Message rules list cannot be empty in rules.json.");
        }
        for (RulesConfig.MessageRuleDef rule : config.getMessageRules()) {
            if (rule.getId() == null || rule.getId().isBlank()) {
                throw new InvalidConfigurationException("Message rule is missing an 'id'.");
            }
            if (rule.getWeight() <= 0) {
                throw new InvalidConfigurationException("Message rule '" + rule.getId() + "' must have a positive weight.");
            }
            if (rule.getPatterns() == null || rule.getPatterns().isEmpty()) {
                throw new InvalidConfigurationException("Message rule '" + rule.getId() + "' has no detection patterns.");
            }
        }
        if (config.getUrlRules() == null || config.getUrlRules().isEmpty()) {
            throw new InvalidConfigurationException("URL rules list cannot be empty in rules.json.");
        }
        for (RulesConfig.UrlRuleDef rule : config.getUrlRules()) {
            if (rule.getId() == null || rule.getId().isBlank()) {
                throw new InvalidConfigurationException("URL rule is missing an 'id'.");
            }
            if (rule.getWeight() <= 0) {
                throw new InvalidConfigurationException("URL rule '" + rule.getId() + "' must have a positive weight.");
            }
        }
    }
}
