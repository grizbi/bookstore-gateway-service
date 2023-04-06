package com.example.gatewayservice.security.jwt.validation;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RouteValidator {

    private final List<String> openEndpoints = List.of(
            "/login",
            "/users"
    );


    public boolean isRouteSecured(ServerHttpRequest request) {
        return !openEndpoints.contains(request.getURI().getPath());
    }

}
