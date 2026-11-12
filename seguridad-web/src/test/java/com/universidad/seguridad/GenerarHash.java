package com.universidad.seguridad;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

// Utilidad del Paso 8 para generar el hash del ADMIN con el mismo PasswordEncoder de la aplicacion.
// Su nombre no termina en Test a proposito: solo corre cuando se pide (mvn test -Dtest=GenerarHash)
@SpringBootTest
class GenerarHash {
    @Autowired PasswordEncoder encoder;

    @Test
    void generarHashAdmin() {
        System.out.println("HASH_ADMIN=" + encoder.encode("admin123"));
        // Copiar el hash resultante para el INSERT de MySQL
    }
}
