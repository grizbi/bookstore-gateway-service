package com.example.gatewayservice.filter;

import com.example.gatewayservice.security.jwt.JwtUtil;
import com.example.gatewayservice.security.jwt.validation.RequestValidator;
import com.example.gatewayservice.security.jwt.validation.RouteValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
@Component
public class AuthenticationFilter implements GlobalFilter {

    private final JwtUtil jwtUtil;
    private final RequestValidator requestValidator;
    private final RouteValidator routeValidator;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest serverHttpRequest = exchange.getRequest();

        if (routeValidator.isRouteSecured(serverHttpRequest)) {
            if(!requestValidator.hasAuthorizationHeader(serverHttpRequest)) {
                log.info("No authorization header");
                return onError(exchange);
            }

            String token = getAuthHeader(serverHttpRequest);

            if (!jwtUtil.validateToken(token)) {
                log.info("Invalid token");
                return this.onError(exchange);
            }
        }

        return chain.filter(exchange);
    }

    private Mono<Void> onError(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    private String getAuthHeader(ServerHttpRequest request) {
        return request.getHeaders().getOrEmpty("Authorization").get(0);
    }
}
