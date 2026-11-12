package com.universidad.seguridad.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;

/**
 * Usuario autenticado con su id y su nombre, ademas del email (username) y el rol.
 * Lo usan las dos superficies: UsuarioDetailsService lo arma desde la base de datos para la
 * sesion, y JwtAuthFilter lo arma desde el token. Asi "authentication.principal.id" funciona
 * igual en @PreAuthorize sin importar con que mecanismo entro el usuario.
 */
public class UsuarioAutenticado extends User {

    private final Long id;
    private final String nombre;

    public UsuarioAutenticado(Long id, String nombre, String email, String contrasenia, String rol, boolean activo) {
        super(email, contrasenia, activo, true, true, true, List.of(new SimpleGrantedAuthority(rol)));
        this.id = id;
        this.nombre = nombre;
    }

    public Long getId() { return id; }

    public String getNombre() { return nombre; }

    public String getRol() {
        return getAuthorities().iterator().next().getAuthority();
    }

    public boolean esAdmin() {
        return "ROLE_ADMIN".equals(getRol());
    }
}
