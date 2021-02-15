package org.alien4cloud.plugin.portal.model;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor

@JsonIgnoreProperties(ignoreUnknown = true)
public class Role {
   String name;
   String description;
   Map<String,List<String>> attributes;

   public boolean equals (Object o) {
      if (! (o instanceof Role)) {
         return false;
      }
      Role or = (Role)o;
      return (or.getName().equals(name));
   }
}
