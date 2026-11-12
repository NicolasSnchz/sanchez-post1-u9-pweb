package com.universidad.seguridad;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Parte 1: sesion, BCrypt, roles, XSS, SQL Injection y CSRF sobre la aplicacion completa (H2)
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class SeguridadSesionTest {

    private static final String PAYLOAD_XSS = "<script>alert(\"XSS\")</script>";
    private static final String PAYLOAD_SQL = "' OR '1'='1";

    @Autowired private MockMvc mvc;
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
        Datos.tarea(tareas, laura, "Preparar informe de laboratorio");
        Datos.tarea(tareas, pedro, "Revisar informe de costos");
    }

    @Test
    void dashboard_sinSesion_redirigeAlLogin() throws Exception {
        mvc.perform(get("/dashboard"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    void registro_guardaLaContraseniaComoHashBCryptDeCosto12YRolUser() throws Exception {
        mvc.perform(post("/registro").with(csrf())
                .param("nombre", "Ana Torres").param("email", "ana@universidad.edu")
                .param("contrasenia", "clave-de-ana-1"))
            .andExpect(redirectedUrl("/login?registrado"));

        Usuario ana = usuarios.findByEmail("ana@universidad.edu").orElseThrow();
        assertTrue(ana.getContrasenia().startsWith("$2a$12$"));
        assertTrue(encoder.matches("clave-de-ana-1", ana.getContrasenia()));
        assertEquals("ROLE_USER", ana.getRol());
    }

    @Test
    void registro_ignoraIdYRolEnviadosEnElFormulario() throws Exception {
        String hashOriginal = admin.getContrasenia();

        mvc.perform(post("/registro").with(csrf())
                .param("id", admin.getId().toString()).param("rol", "ROLE_ADMIN")
                .param("nombre", "Intruso").param("email", "intruso@universidad.edu")
                .param("contrasenia", "clave-intrusa-1"))
            .andExpect(redirectedUrl("/login?registrado"));

        assertEquals(hashOriginal, usuarios.findById(admin.getId()).orElseThrow().getContrasenia());
        assertEquals("ROLE_USER", usuarios.findByEmail("intruso@universidad.edu").orElseThrow().getRol());
    }

    @Test
    void registro_correoRepetido_vuelveAlFormularioConElError() throws Exception {
        mvc.perform(post("/registro").with(csrf())
                .param("nombre", "Otra Laura").param("email", "laura@universidad.edu")
                .param("contrasenia", "clave-larga-1"))
            .andExpect(status().isOk())
            .andExpect(view().name("auth/registro"))
            .andExpect(content().string(containsString("El correo ya esta registrado")));
    }

    @Test
    void login_credencialesValidas_autenticaYVaAlDashboard() throws Exception {
        mvc.perform(formLogin("/login").user("laura@universidad.edu").password(Datos.CLAVE))
            .andExpect(authenticated().withUsername("laura@universidad.edu"))
            .andExpect(redirectedUrl("/dashboard"));
    }

    @Test
    void login_contraseniaIncorrecta_noAutenticaYMuestraError() throws Exception {
        mvc.perform(formLogin("/login").user("laura@universidad.edu").password("otra-clave"))
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"));
    }

    @Test
    void admin_conRolUser_respondeForbidden() throws Exception {
        mvc.perform(get("/admin").with(user(Datos.principal(laura))))
            .andExpect(status().isForbidden());
    }

    @Test
    void admin_conRolAdmin_muestraLaListaDeUsuarios() throws Exception {
        mvc.perform(get("/admin").with(user(Datos.principal(admin))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("laura@universidad.edu")))
            .andExpect(content().string(containsString("pedro@universidad.edu")));
    }

    @Test
    void dashboard_soloMuestraElEnlaceDeAdministracionAlAdmin() throws Exception {
        mvc.perform(get("/dashboard").with(user(Datos.principal(laura))))
            .andExpect(content().string(not(containsString("Panel de Administración"))));
        mvc.perform(get("/dashboard").with(user(Datos.principal(admin))))
            .andExpect(content().string(containsString("Panel de Administración")));
    }

    @Test
    void dashboard_nombreConScript_seMuestraEscapadoYNoComoEtiqueta() throws Exception {
        Usuario atacante = Datos.usuario(usuarios, encoder, PAYLOAD_XSS, "xss@universidad.edu", "ROLE_USER");

        mvc.perform(get("/dashboard").with(user(Datos.principal(atacante))))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;")))
            .andExpect(content().string(not(containsString(PAYLOAD_XSS))));
    }

    @Test
    void buscar_conPayloadDeSqlInjection_noDevuelveNingunaTarea() throws Exception {
        List<?> resultado = (List<?>) mvc.perform(get("/tareas").param("texto", PAYLOAD_SQL)
                .with(user(Datos.principal(laura))))
            .andExpect(status().isOk())
            .andReturn().getModelAndView().getModel().get("tareas");

        assertTrue(resultado.isEmpty());
    }

    @Test
    void buscar_comoUser_soloEncuentraSusPropiasTareas() throws Exception {
        @SuppressWarnings("unchecked")
        List<Tarea> resultado = (List<Tarea>) mvc.perform(get("/tareas").param("texto", "informe")
                .with(user(Datos.principal(laura))))
            .andReturn().getModelAndView().getModel().get("tareas");

        assertEquals(List.of("Preparar informe de laboratorio"), resultado.stream().map(Tarea::getTitulo).toList());
    }

    @Test
    void buscar_comoAdmin_encuentraLasTareasDeTodos() throws Exception {
        @SuppressWarnings("unchecked")
        List<Tarea> resultado = (List<Tarea>) mvc.perform(get("/tareas").param("texto", "informe")
                .with(user(Datos.principal(admin))))
            .andReturn().getModelAndView().getModel().get("tareas");

        assertEquals(2, resultado.size());
    }

    @Test
    void logout_sinTokenCsrf_respondeForbidden() throws Exception {
        mvc.perform(post("/logout").with(user(Datos.principal(laura))))
            .andExpect(status().isForbidden());
    }

    @Test
    void logout_conTokenCsrf_cierraLaSesionYVaAlLogin() throws Exception {
        mvc.perform(post("/logout").with(user(Datos.principal(laura))).with(csrf()))
            .andExpect(redirectedUrl("/login?logout"));
    }

    @Test
    void crearTarea_sinTokenCsrf_respondeForbidden() throws Exception {
        mvc.perform(post("/tareas").param("titulo", "Tarea sin token").with(user(Datos.principal(laura))))
            .andExpect(status().isForbidden());
    }
}
