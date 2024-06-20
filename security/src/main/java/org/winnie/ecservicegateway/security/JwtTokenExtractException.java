package org.winnie.ecservicegateway.security;

/**
 * Jwt token extract exception.
 */
public class JwtTokenExtractException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  public JwtTokenExtractException(String message) {
    super(message);
  }
}
