package com.sushma.apigateway.filter;

import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.sushma.apigateway.util.JwtUtil;

import reactor.core.publisher.Mono;

/**
 * JwtAuthenticationFilter – Spring Cloud Gateway GatewayFilterFactory.
 *
 * Applied to every protected route in application.yml via:
 *   filters:
 *     - JwtAuthenticationFilter
 *
 * FIX for Spring Framework 7 / Spring Boot 4.x:
 *   HttpHeaders.containsKey(String) was REMOVED from the reactive HttpHeaders API.
 *   Replace with headers.getFirst(HttpHeaders.AUTHORIZATION) which returns null
 *   when the header is absent — one null check covers both cases cleanly.
 *
 * OLD (broken in Spring Framework 7):
 *   if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) { ... }
 *
 * NEW (works in Spring Framework 7):
 *   String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);
 *   if (authHeader == null) { ... }
 */
@Component
public class JwtAuthenticationFilter
        extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Autowired
    private JwtUtil jwtUtil;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            ServerHttpRequest request = exchange.getRequest();
            HttpHeaders headers = request.getHeaders();

            // ── Step 1: Get Authorization header ──────────────────────────
            // FIX: getFirst() returns null if header is absent.
            // This replaces the removed containsKey() call.
            String authHeader = headers.getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null) {
                return unauthorizedResponse(exchange,
                        "Missing Authorization header",
                        "Add header: Authorization: Bearer <your-token>");
            }

            // ── Step 2: Validate Bearer format ────────────────────────────
            if (!authHeader.startsWith("Bearer ")) {
                return unauthorizedResponse(exchange,
                        "Invalid Authorization format",
                        "Header must start with 'Bearer '. Example: Authorization: Bearer eyJhb...");
            }

            String token = authHeader.substring(7);

            // ── Step 3: Validate JWT ───────────────────────────────────────
            if (!jwtUtil.isTokenValid(token)) {
                return unauthorizedResponse(exchange,
                        "Invalid or expired token",
                        "Re-login via POST /gateway/user/authenticate to get a fresh token.");
            }

            // ── Step 4: Token valid – enrich request and forward ──────────
            // Add X-Auth-User header so downstream services know the caller.
            String username = jwtUtil.getUsernameFromToken(token);
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-Auth-User", username)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        };
    }

    // ── Helper: structured 401 JSON response ───────────────────────────────

    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange,
                                            String error,
                                            String hint) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String body = String.format(
                "{\"status\":\"401 Unauthorized\",\"error\":\"%s\",\"hint\":\"%s\"}",
                error, hint);

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        org.springframework.core.io.buffer.DataBuffer buffer =
                response.bufferFactory().wrap(bytes);

        return response.writeWith(Mono.just(buffer));
    }

    // ── Config (required by AbstractGatewayFilterFactory) ──────────────────
    public static class Config {
        // empty – extend if you need per-route configuration
    }
}