package org.winnie.ecservicegateway.security.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * Role dto.
 */
@Getter
@Setter
public class RoleDto {
  private String id;
  private String name;
  private String description;
  private List<AccessGroupDto> accessGroups;

}
