package org.winnie.ecservicegateway.security.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * Access group dto.
 */
@Getter
@Setter
public class AccessGroupDto {
  private String id;
  private String name;
  private String description;
  private String accessRights;

}
