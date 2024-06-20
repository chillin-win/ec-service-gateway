package org.winnie.ecservicegateway.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * User dto.
 */
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserDto {

  private String id;
  private String username;
  private String firstName;
  private String lastName;
  private List<RoleDto> roles;
  private GroupDto group;
  private String datasetMode;
  private List<DatasetDto> datasets;
  private Boolean internal;

}

