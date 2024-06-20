package org.winnie.ecservicegateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

/**
 * Resource server.
 */
@EnableWebFluxSecurity
public class SecurityConfig {

  /**
   * Configuration for springSecurityFilterChain in order to override default behavior of Spring
   * Security.
   *
   * @param http {@link ServerHttpSecurity} object contains HTTP security request information
   * @return {@link SecurityWebFilterChain} object
   */
  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    http.authorizeExchange(exchanges ->
      exchanges
        .pathMatchers(HttpMethod.GET,
            "/v3/api-docs/**",
            "/swagger-resources/**",
            "/swagger-ui.html",
            "/webjars/**",
            "/healthcheck",
            "/version",
            "/credentials/consent-screen/**"
        ).permitAll()
        .anyExchange().authenticated())
      .csrf().disable()
      .oauth2ResourceServer().jwt();

    http.cors();

    return http.build();
  }

  @Bean
  CorsConfigurationSource corsConfiguration() {
    CorsConfiguration corsConfig = new CorsConfiguration();
    corsConfig.applyPermitDefaultValues();
    corsConfig.addAllowedMethod(HttpMethod.OPTIONS);
    corsConfig.addAllowedMethod(HttpMethod.PUT);
    corsConfig.addAllowedMethod(HttpMethod.DELETE);
    corsConfig.addAllowedMethod(HttpMethod.GET);
    corsConfig.addAllowedOrigin("*");

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", corsConfig);

    return source;
  }
}
