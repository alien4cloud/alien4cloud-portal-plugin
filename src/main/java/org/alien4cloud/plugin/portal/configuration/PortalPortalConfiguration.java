package org.alien4cloud.plugin.portal.configuration;

import lombok.Getter;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;

@Getter
@Setter
@Component
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "portal")
public class PortalPortalConfiguration {
   /* PD */
   private Map<String,String> all;

   /* ZD */
   private Map<String,Map<String,String>> zones;

}