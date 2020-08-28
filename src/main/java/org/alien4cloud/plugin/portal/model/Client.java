package org.alien4cloud.plugin.portal.model;

import lombok.Getter;
import lombok.Setter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@Getter
@Setter

@JsonIgnoreProperties(ignoreUnknown = true)
public class Client {
   String id;
   String clientId;
   List<String> redirectUris;
   List<String> webOrigins;
}
