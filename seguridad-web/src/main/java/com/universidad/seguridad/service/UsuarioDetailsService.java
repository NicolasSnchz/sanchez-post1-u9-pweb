package com.universidad.seguridad.service;

import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.UsuarioRepository;
import com.universidad.seguridad.security.UsuarioAutenticado;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UsuarioDetailsService implements UserDetailsService {

    private final UsuarioRepository repo;

    public UsuarioDetailsService(UsuarioRepository repo) {
        this.repo = repo;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario u = repo.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + email));

        // UsuarioAutenticado en vez de User.builder(): ademas del email, el hash BCrypt y el rol,
        // lleva el id y el nombre que usan @PreAuthorize y el dashboard
        return new UsuarioAutenticado(u.getId(), u.getNombre(), u.getEmail(),
            u.getContrasenia(), u.getRol(), u.isActivo());
    }
}
