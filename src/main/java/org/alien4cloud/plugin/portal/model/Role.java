package org.alien4cloud.plugin.portal.model;

import lombok.Getter;
import lombok.Setter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

@Getter
@Setter

@JsonIgnoreProperties(ignoreUnknown = true)
public class Role {
   String name;
   String description;
   Map<String,List<String>> attributes;
}
