package com.example.gatewayservice.security.jwt.validation;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

@Component
public class RequestValidator {

    public boolean hasAuthorizationHeader(ServerHttpRequest request) {
        return request.getHeaders().containsKey("Authorization");
    }
}
