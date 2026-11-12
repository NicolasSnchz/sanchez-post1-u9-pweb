package com.universidad.seguridad;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import com.universidad.seguridad.security.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Parte 2: la API stateless con JWT, y su convivencia con la sesion de la Parte 1
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ApiJwtTest {

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper json;
    @Autowired private UsuarioRepository usuarios;
    @Autowired private TareaRepository tareas;
    @Autowired private PasswordEncoder encoder;
    @Value("${jwt.secret}") private String secreto;

    private Usuario admin;
    private Usuario laura;

    @BeforeEach
    void setUp() {
        admin = Datos.usuario(usuarios, encoder, "Administrador", "admin@universidad.edu", "ROLE_ADMIN");
        laura = Datos.usuario(usuarios, encoder, "Laura Gomez", "laura@universidad.edu", "ROLE_USER");
        Usuario pedro = Datos.usuario(usuarios, encoder, "Pedro Rojas", "pedro@universidad.edu", "ROLE_USER");
        Datos.tarea(tareas, laura, "Tarea de Laura");
        Datos.tarea(tareas, pedro, "Tarea de Pedro");
    }

    @Test
    void login_credencialesValidas_devuelveUnTokenConElRol() throws Exception {
        JsonNode respuesta = login("admin@universidad.edu", Datos.CLAVE);

        assertFalse(respuesta.get("token").asText().isBlank());
        assertEquals("ROLE_ADMIN", respuesta.get("rol").asText());
    }

    @Test
    void login_contraseniaIncorrecta_responde401SinToken() throws Exception {
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"admin@universidad.edu\",\"contrasenia\":\"incorrecta\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.token").doesNotExist());
    }

    @Test
    void tareas_conToken_devuelveSoloLasDelUsuarioYSinDatosSensibles() throws Exception {
        String token = login("laura@universidad.edu", Datos.CLAVE).get("token").asText();

        mvc.perform(get("/api/tareas").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(1))
            .andExpect(jsonPath("$[0].titulo").value("Tarea de Laura"))
            .andExpect(content().string(not(containsString("contrasenia"))))
            .andExpect(content().string(not(containsString("$2a$"))));
    }

    @Test
    void tareas_sinToken_responde401() throws Exception {
        mvc.perform(get("/api/tareas"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void tareas_conFirmaModificada_responde401() throws Exception {
        String token = login("laura@universidad.edu", Datos.CLAVE).get("token").asText();
        int i = token.length() - 10; // un caracter en medio de la firma
        String alterado = token.substring(0, i) + (token.charAt(i) == 'A' ? 'B' : 'A') + token.substring(i + 1);

        mvc.perform(get("/api/tareas").header("Authorization", "Bearer " + alterado))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void tareas_conTokenExpirado_responde401() throws Exception {
        String vencido = new JwtUtil(secreto, -1_000).generarToken(laura.getId(), laura.getEmail(), "ROLE_USER");

        mvc.perform(get("/api/tareas").header("Authorization", "Bearer " + vencido))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void adminUsuarios_conTokenDeUser_responde403() throws Exception {
        String token = login("laura@universidad.edu", Datos.CLAVE).get("token").asText();

        mvc.perform(get("/api/admin/usuarios").header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }

    @Test
    void adminUsuarios_conTokenDeAdmin_listaUsuariosSinHashes() throws Exception {
        String token = login("admin@universidad.edu", Datos.CLAVE).get("token").asText();

        mvc.perform(get("/api/admin/usuarios").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.length()").value(3))
            .andExpect(content().string(not(containsString("$2a$"))));
    }

    @Test
    void api_esStateless_noCreaSesionNiCookie() throws Exception {
        String token = login("laura@universidad.edu", Datos.CLAVE).get("token").asText();

        MvcResult resultado = mvc.perform(get("/api/tareas").header("Authorization", "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(header().doesNotExist("Set-Cookie"))
            .andReturn();
        assertNull(resultado.getRequest().getSession(false));
    }

    @Test
    void sesionYJwt_convivenSinQueUnoAutentiqueAlOtro() throws Exception {
        // 1. Sesion de la Parte 1: login por formulario y dashboard
        MockHttpSession sesion = (MockHttpSession) mvc.perform(
                formLogin("/login").user("laura@universidad.edu").password(Datos.CLAVE))
            .andExpect(redirectedUrl("/dashboard"))
            .andReturn().getRequest().getSession(false);
        mvc.perform(get("/dashboard").session(sesion)).andExpect(status().isOk());

        // 2. Al mismo tiempo, la API con su token
        String token = login("laura@universidad.edu", Datos.CLAVE).get("token").asText();
        mvc.perform(get("/api/tareas").header("Authorization", "Bearer " + token)).andExpect(status().isOk());

        // 3. Ninguno depende del otro: la cookie de sesion no abre la API y el token no abre las vistas
        mvc.perform(get("/api/tareas").session(sesion)).andExpect(status().isUnauthorized());
        mvc.perform(get("/dashboard").header("Authorization", "Bearer " + token))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login"));

        // 4. La sesion sigue viva despues de usar la API
        mvc.perform(get("/dashboard").session(sesion)).andExpect(status().isOk());
    }

    private JsonNode login(String email, String contrasenia) throws Exception {
        String cuerpo = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(new java.util.HashMap<>(java.util.Map.of(
                    "email", email, "contrasenia", contrasenia)))))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        return json.readTree(cuerpo);
    }
}
