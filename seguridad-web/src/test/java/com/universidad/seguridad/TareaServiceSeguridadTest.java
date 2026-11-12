package com.universidad.seguridad;

import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import com.universidad.seguridad.service.TareaService;
import com.universidad.seguridad.service.UsuarioService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

// @PreAuthorize en los servicios: la regla se cumple aunque alguien llame al servicio sin pasar por la URL
@SpringBootTest
@Transactional
class TareaServiceSeguridadTest {

    @Autowired private TareaService tareaService;
    @Autowired private UsuarioService usuarioService;
    @Autowired private UsuarioRepository usuarios;
    @Autowired private TareaRepository tareas;
    @Autowired private PasswordEncoder encoder;

    private Usuario admin;
    private Usuario laura;
    private Usuario pedro;

    @BeforeEach
    void setUp() {
        admin = Datos.usuario(usuarios, encoder, "Administrador", "admin@universidad.edu", "ROLE_ADMIN");
        laura = Datos.usuario(usuarios, encoder, "Laura Gomez", "laura@universidad.edu", "ROLE_USER");
        pedro = Datos.usuario(usuarios, encoder, "Pedro Rojas", "pedro@universidad.edu", "ROLE_USER");
        Datos.tarea(tareas, pedro, "Tarea de Pedro");
    }

    @AfterEach
    void limpiarContexto() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void listarDe_userPidiendoSusPropiasTareas_lasDevuelve() {
        autenticar(laura);
        assertTrue(tareaService.listarDe(laura.getId()).isEmpty());
    }

    @Test
    void listarDe_userPidiendoTareasAjenas_lanzaAccessDenied() {
        autenticar(laura);
        assertThrows(AccessDeniedException.class, () -> tareaService.listarDe(pedro.getId()));
    }

    @Test
    void listarDe_adminPidiendoTareasAjenas_lasDevuelve() {
        autenticar(admin);
        assertEquals(1, tareaService.listarDe(pedro.getId()).size());
    }

    @Test
    void listarTodosLosUsuarios_conRolUser_lanzaAccessDenied() {
        autenticar(laura);
        assertThrows(AccessDeniedException.class, () -> usuarioService.listarTodos());
    }

    private void autenticar(Usuario usuario) {
        var principal = Datos.principal(usuario);
        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities()));
    }
}
