package com.universidad.seguridad.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    // La clave y la expiracion vienen de application.properties, que a su vez lee la variable de
    // entorno JWT_SECRET: la clave no queda escrita en el codigo fuente (ver README)
    private final SecretKey clave;
    private final long expiracionMs;

    public JwtUtil(@Value("${jwt.secret}") String secreto,
                   @Value("${jwt.expiracion-ms}") long expiracionMs) {
        this.clave = Keys.hmacShaKeyFor(secreto.getBytes(StandardCharsets.UTF_8));
        this.expiracionMs = expiracionMs;
    }

    public String generarToken(Long id, String email, String rol) {
        return Jwts.builder()
            .subject(email)
            .claim("uid", id)
            .claim("rol", rol)
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + expiracionMs))
            .signWith(clave)
            .compact();
    }

    public String extraerEmail(String token) {
        return parsearClaims(token).getSubject();
    }

    public String extraerRol(String token) {
        return parsearClaims(token).get("rol", String.class);
    }

    public Long extraerId(String token) {
        return ((Number) parsearClaims(token).get("uid")).longValue();
    }

    public boolean esValido(String token) {
        try {
            parsearClaims(token); // lanza excepcion si la firma o la expiracion no son validas
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false; // firma invalida, token expirado o malformado
        }
    }

    private Claims parsearClaims(String token) {
        return Jwts.parser()
            .verifyWith(clave)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }
}
