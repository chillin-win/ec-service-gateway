package org.winnie.ecservicegateway.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractNameValueGatewayFilterFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.winnie.ecservicegateway.security.dto.AccessGroupDto;
import org.winnie.ecservicegateway.security.dto.DatasetDto;
import org.winnie.ecservicegateway.security.dto.ResponseDto;
import org.winnie.ecservicegateway.security.dto.UserDto;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.cloud.gateway.support.GatewayToStringStyler.filterToStringCreator;

/**
 * Jwt filter gateway filter factory.
 */
@Component
public class JwtFilterGatewayFilterFactory extends AbstractNameValueGatewayFilterFactory {

    public static final String X_JWT_USER_HEADER = "X-jwt-user";
    public static final String X_JWT_FIRST_NAME_HEADER = "X-jwt-first-name";
    public static final String X_JWT_LAST_NAME_HEADER = "X-jwt-last-name";
    public static final String X_USER_GROUP_HEADER = "X-user-group";
    public static final String X_USER_ACCESS_RIGHTS_HEADER = "X-user-rights";
    public static final String X_USER_DATASETS_HEADER = "X-user-datasets";
    public static final String X_USER_INTERNAL_HEADER = "X-user-internal";
    public static final String USER_INFO_URL = "/users";
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtFilterGatewayFilterFactory.class);
    @Value("${userservice.url}")
    private String userServiceUrl;

    @Override
    public GatewayFilter apply(NameValueConfig config) {
        return new GatewayFilter() {
            @Override
            public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//                return chain.filter(exchange);
                return addSomeUserInfoToHeaders(exchange)
//                        .flatMap(request -> addUserMetadataToHeaders(request))
                        .flatMap(request -> chain.filter(exchange.mutate().request(request).build()));
            }

            @Override
            public String toString() {
                return filterToStringCreator(JwtFilterGatewayFilterFactory.this)
                        .append(config.getName(), config.getValue()).toString();
            }
        };
    }

    private JWTClaimsSet getJwtClaimsSet(ServerWebExchange exchange) throws ParseException {
        String token = extractJwtToken(exchange.getRequest());
        SignedJWT jwt = SignedJWT.parse(token);

        return jwt.getJWTClaimsSet();
    }

    private String extractJwtToken(ServerHttpRequest request) {
        if (!request.getHeaders().containsKey("Authorization")) {
            throw new JwtTokenExtractException("Authorization header is missing");
        }

        List<String> headers = request.getHeaders().get("Authorization");

        String credential = headers.get(0).trim();
        String[] components = credential.split("\\s");

        if (components.length != 2) {
            throw new JwtTokenExtractException("Malformed Authorization content");
        }

        if (!components[0].equals("Bearer")) {
            throw new JwtTokenExtractException("Bearer is needed");
        }

        return components[1].trim();
    }

    private Mono<ServerHttpRequest> addSomeUserInfoToHeaders(ServerWebExchange exchange) {
        String username = "";
        String firstName = "";
        String lastName = "";

        try {
            JWTClaimsSet jwtClaimsSet = getJwtClaimsSet(exchange);

            username = jwtClaimsSet.getStringClaim("preferred_username");
            firstName = jwtClaimsSet.getStringClaim("given_name");
            lastName = jwtClaimsSet.getStringClaim("family_name");
        } catch (ParseException | JwtTokenExtractException e) {
            LOGGER.error(e.getMessage(), e);
        }
        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate()
                .header(X_JWT_USER_HEADER, username);

        String path = exchange.getRequest().getPath().pathWithinApplication().value();
        HttpMethod method = exchange.getRequest().getMethod();
        if (path.equals(USER_INFO_URL) && method == HttpMethod.PUT) {
            requestBuilder = requestBuilder
                    .header(X_JWT_FIRST_NAME_HEADER, firstName)
                    .header(X_JWT_LAST_NAME_HEADER, lastName);
        }

        return Mono.just(requestBuilder.build());
    }

    private Mono<ServerHttpRequest> addUserMetadataToHeaders(ServerHttpRequest request) {
        String username = request.getHeaders().get(X_JWT_USER_HEADER).get(0);

        return getUserMetaData(username)
                .map(userMetadataMap -> request.mutate()
                        .header(X_USER_ACCESS_RIGHTS_HEADER, userMetadataMap.get(X_USER_ACCESS_RIGHTS_HEADER))
                        .header(X_USER_DATASETS_HEADER, userMetadataMap.get(X_USER_DATASETS_HEADER))
                        .header(X_USER_GROUP_HEADER, userMetadataMap.get(X_USER_GROUP_HEADER))
                        .header(X_USER_GROUP_HEADER, userMetadataMap.get(X_USER_GROUP_HEADER))
                        .header(X_USER_INTERNAL_HEADER, userMetadataMap.get(X_USER_INTERNAL_HEADER))
                        .build());
    }

    private Mono<Map<String, String>> getUserMetaData(String username) {
        return WebClient.builder()
                .baseUrl(userServiceUrl)
                .build()
                .get()
                .uri(USER_INFO_URL)
                .header(X_JWT_USER_HEADER, username)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(jsonNode -> {
                    Map<String, String> userMetadataMap = new HashMap<>();
                    userMetadataMap.put(X_USER_ACCESS_RIGHTS_HEADER, extractAccessRights(jsonNode));
                    userMetadataMap.put(X_USER_DATASETS_HEADER, extractDatasets(jsonNode));
                    userMetadataMap.put(X_USER_GROUP_HEADER, extractUserGroup(jsonNode));
                    userMetadataMap.put(X_USER_INTERNAL_HEADER, extractUserInternal(jsonNode));

                    return userMetadataMap;
                });
    }

    private String extractAccessRights(JsonNode jsonNode) {
        ObjectMapper mapper = new ObjectMapper();
        ResponseDto<UserDto> responseDto =
                mapper.convertValue(jsonNode, new TypeReference<ResponseDto<UserDto>>() {
                    // NOP
                });

        List<String> accessRightNames = responseDto.getData()
                .getRoles()
                .stream()
                .flatMap(roleDto -> roleDto.getAccessGroups().stream())
                .map(AccessGroupDto::getAccessRights)
                .collect(Collectors.toList());

        return String.join(",", accessRightNames);
    }

    private String extractDatasets(JsonNode jsonNode) {
        ObjectMapper mapper = new ObjectMapper();
        ResponseDto<UserDto> responseDto =
                mapper.convertValue(jsonNode, new TypeReference<ResponseDto<UserDto>>() {
                    // NOP
                });

        UserDto userDto = responseDto.getData();
        if (userDto.getDatasets() != null) {
            List<String> datasetNames = userDto.getDatasets()
                    .stream()
                    .map(DatasetDto::getName)
                    .collect(Collectors.toList());

            return String.join(",", datasetNames);
        }

        return "";
    }

    private String extractUserGroup(JsonNode jsonNode) {
        ObjectMapper mapper = new ObjectMapper();
        ResponseDto<UserDto> responseDto =
                mapper.convertValue(jsonNode, new TypeReference<ResponseDto<UserDto>>() {
                    // NOP
                });

        UserDto userDto = responseDto.getData();
        if (userDto.getGroup() != null) {
            return userDto.getGroup().getId();
        }

        return "";
    }

    private String extractUserInternal(JsonNode jsonNode) {
        ObjectMapper mapper = new ObjectMapper();
        ResponseDto<UserDto> responseDto =
                mapper.convertValue(jsonNode, new TypeReference<ResponseDto<UserDto>>() {
                    // NOP
                });

        UserDto userDto = responseDto.getData();
        if (userDto.getInternal() != null) {
            return userDto.getInternal().toString();
        }

        return Boolean.FALSE.toString();
    }

    public void setUserServiceUrl(String userServiceUrl) {
        this.userServiceUrl = userServiceUrl;
    }
}
