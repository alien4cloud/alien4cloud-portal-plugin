package org.alien4cloud.plugin.portal.model;

import lombok.Getter;
import lombok.Setter;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Getter
@Setter

@JsonIgnoreProperties(ignoreUnknown = true)
public class Token {
   @JsonAlias("access_token")
   String accessToken;
}
