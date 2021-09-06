package com.example.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties.Jwt;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final Environment environment;

    public AuthorizationHeaderFilter(final Environment environment) {
        super(Config.class);
        this.environment = environment;
    }

    // login -> token -> user (with token) -> header(include token)
    @Override
    public GatewayFilter apply(final Config config) {
        return (exchange, chain) -> {
            final ServerHttpRequest request = exchange.getRequest();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No Authorization Header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer", "");

            if (!isJwtValid(jwt)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        };
    }

    private Mono<Void> onError(final ServerWebExchange exchange, final String errorMessage, final HttpStatus httpStatus) {
        final ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(errorMessage);
        return response.setComplete();
    }

    private boolean isJwtValid(final String jwt) {


        String subject = Jwts.parser()
            .setSigningKey(environment.getProperty("token.secret"))
            .parseClaimsJws(jwt).getBody()
            .getSubject();

        if (!StringUtils.hasText(subject)) {
            return false;
        }

        return true;
    }

    public static class Config {

    }

}
