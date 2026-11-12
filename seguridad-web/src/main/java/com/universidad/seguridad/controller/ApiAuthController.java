package com.universidad.seguridad.controller;

import com.universidad.seguridad.security.JwtUtil;
import com.universidad.seguridad.security.UsuarioAutenticado;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class ApiAuthController {

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    public ApiAuthController(AuthenticationManager authManager, JwtUtil jwtUtil) {
        this.authManager = authManager;
        this.jwtUtil = jwtUtil;
    }

    public record LoginRequest(String email, String contrasenia) {}
    public record LoginResponse(String token, String email, String rol) {}

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest req) {
        // Reutiliza el MISMO DaoAuthenticationProvider de la Parte 1 (UsuarioDetailsService y
        // BCryptPasswordEncoder): las credenciales se validan igual, solo cambia lo que se
        // devuelve al final (un token en vez de una cookie de sesion)
        Authentication auth = authManager.authenticate(
            new UsernamePasswordAuthenticationToken(req.email(), req.contrasenia())
        );
        UsuarioAutenticado usuario = (UsuarioAutenticado) auth.getPrincipal();
        String token = jwtUtil.generarToken(usuario.getId(), usuario.getUsername(), usuario.getRol());
        return new LoginResponse(token, usuario.getUsername(), usuario.getRol());
    }

    // Credenciales incorrectas o cuenta desactivada: 401 sin token, con un mensaje generico que
    // no revela si el correo existe
    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Map<String, String> credencialesInvalidas() {
        return Map.of("error", "Credenciales invalidas");
    }
}
