package com.universidad.seguridad.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) { this.jwtUtil = jwtUtil; }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);

            if (jwtUtil.esValido(token)) {
                // El mismo tipo de principal que crea la sesion, armado con los datos del token:
                // no se consulta la base de datos en cada peticion
                var usuario = new UsuarioAutenticado(jwtUtil.extraerId(token), null,
                    jwtUtil.extraerEmail(token), "", jwtUtil.extraerRol(token), true);
                var authToken = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
                // Puebla el SecurityContext manualmente: no hay sesion de la que Spring Security
                // pueda recuperar el usuario en la siguiente peticion, asi que este filtro se
                // ejecuta en CADA peticion a /api/**
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            // Si el token no es valido, simplemente no se autentica: apiFilterChain decide si
            // la ruta requeria autenticacion y responde 401 en ese caso
        }

        chain.doFilter(request, response);
    }
}
