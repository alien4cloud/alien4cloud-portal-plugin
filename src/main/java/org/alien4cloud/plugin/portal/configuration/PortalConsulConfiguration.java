package org.alien4cloud.plugin.portal.configuration;

import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "portal.consul")
public class PortalConsulConfiguration {

    private String url;
    private String certificate;
    private String key;
}