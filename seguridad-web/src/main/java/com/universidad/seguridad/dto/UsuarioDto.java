package com.universidad.seguridad.dto;

import com.universidad.seguridad.model.Usuario;

/** Lo que la API expone de un usuario: nunca el hash de la contrasena. */
public record UsuarioDto(Long id, String nombre, String email, String rol, boolean activo) {

    public static UsuarioDto de(Usuario usuario) {
        return new UsuarioDto(usuario.getId(), usuario.getNombre(), usuario.getEmail(),
            usuario.getRol(), usuario.isActivo());
    }
}
