package org.alien4cloud.plugin.portal.configuration;

import static alien4cloud.utils.AlienUtils.safe;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import org.apache.commons.lang.StringUtils;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;

@Getter
@Setter
@Slf4j
@Component
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "portal")
public class PortalPortalConfiguration {
   /* PD */
   private Map<String,String> all;

   /* ZD */
   private Map<String,Map<String,String>> zones;

   /**
    * look for a configuration parameter:
    *   - as a ZD parameter
    *   - if not set, as a PD parameter
    **/
   public String getParameter (String zone, String parameter) {
      String result = safe(safe(getZones()).get(zone)).get(parameter);
      log.debug ("Parameter {} ({}): {}", parameter, zone, result);
      if (StringUtils.isBlank(result)) {
         result = safe(getAll()).get(parameter);
         log.debug ("Parameter {} (ALL): {}", parameter, result);
      }
      if (result == null) {
         result = "";
      }
      return result;
   }

}