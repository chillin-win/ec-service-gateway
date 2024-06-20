package org.winnie.ecservicegateway.security.dto;

import lombok.Getter;
import lombok.Setter;

/**
 * Response dto.
 */
@Getter
@Setter
public class ResponseDto<T> {
  private Boolean success;
  private String message;
  private T data;

}
