package com.universidad.seguridad.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

// Prueba unitaria: JwtUtil se crea con new, sin contexto de Spring
class JwtUtilTest {

    private static final String SECRETO = "clave-de-prueba-de-al-menos-32-bytes-para-hs256";

    private final JwtUtil jwt = new JwtUtil(SECRETO, 3_600_000);

    @Test
    void generarToken_llevaEmailRolEIdDelUsuario() {
        String token = jwt.generarToken(7L, "ana@universidad.edu", "ROLE_USER");

        assertTrue(jwt.esValido(token));
        assertEquals("ana@universidad.edu", jwt.extraerEmail(token));
        assertEquals("ROLE_USER", jwt.extraerRol(token));
        assertEquals(Long.valueOf(7), jwt.extraerId(token));
    }

    @Test
    void esValido_conUnCaracterDeLaFirmaCambiado_esFalso() {
        String token = jwt.generarToken(7L, "ana@universidad.edu", "ROLE_USER");
        // se cambia un caracter en medio de la firma: el ultimo solo lleva bits de relleno en base64url
        int i = token.length() - 10;
        String alterado = token.substring(0, i) + (token.charAt(i) == 'A' ? 'B' : 'A') + token.substring(i + 1);

        assertFalse(jwt.esValido(alterado));
    }

    @Test
    void esValido_conRolCambiadoEnElPayload_esFalso() {
        // un atacante no puede ascenderse a ADMIN editando el payload: la firma deja de coincidir
        String token = jwt.generarToken(7L, "ana@universidad.edu", "ROLE_USER");
        String[] partes = token.split("\\.");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(partes[1]));
        String payloadAdmin = java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payload.replace("ROLE_USER", "ROLE_ADMIN").getBytes());

        assertFalse(jwt.esValido(partes[0] + "." + payloadAdmin + "." + partes[2]));
    }

    @Test
    void esValido_tokenExpirado_esFalso() {
        JwtUtil yaVencido = new JwtUtil(SECRETO, -1_000);
        assertFalse(jwt.esValido(yaVencido.generarToken(7L, "ana@universidad.edu", "ROLE_USER")));
    }

    @Test
    void esValido_tokenFirmadoConOtraClave_esFalso() {
        JwtUtil otraClave = new JwtUtil("otra-clave-distinta-de-al-menos-32-bytes-de-largo", 3_600_000);
        assertFalse(jwt.esValido(otraClave.generarToken(7L, "ana@universidad.edu", "ROLE_ADMIN")));
    }

    @Test
    void esValido_textoQueNoEsUnToken_esFalso() {
        assertFalse(jwt.esValido("eyJhbGciOiJIUzI1NiJ9.token.modificado"));
        assertFalse(jwt.esValido(""));
    }
}
