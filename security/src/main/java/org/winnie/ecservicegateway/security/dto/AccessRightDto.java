package org.winnie.ecservicegateway.security.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * Access right dto.
 */
@Getter
@Setter
public class AccessRightDto {
  private String id;
  private String name;
  private String description;
  private String constrains;

}
