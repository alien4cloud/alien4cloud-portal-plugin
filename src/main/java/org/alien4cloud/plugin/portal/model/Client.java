package org.alien4cloud.plugin.portal.model;

import lombok.Getter;
import lombok.Setter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

@Getter
@Setter

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Client {
   String id;
   String clientId;
   String rootUrl;
   String adminUrl;
   String baseUrl;
   boolean enabled;
   boolean publicClient;
   List<String> redirectUris;
   List<String> webOrigins;
}
