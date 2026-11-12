package com.universidad.seguridad;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import com.universidad.seguridad.security.UsuarioAutenticado;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Crea usuarios y tareas para las pruebas, con el mismo BCrypt de la aplicacion. */
public final class Datos {

    public static final String CLAVE = "clave-segura-1";

    private Datos() {
    }

    public static Usuario usuario(UsuarioRepository repo, PasswordEncoder encoder,
                                  String nombre, String email, String rol) {
        Usuario u = new Usuario();
        u.setNombre(nombre);
        u.setEmail(email);
        u.setContrasenia(encoder.encode(CLAVE));
        u.setRol(rol);
        return repo.save(u);
    }

    public static Tarea tarea(TareaRepository repo, Usuario propietario, String titulo) {
        return repo.save(new Tarea(titulo, "Descripcion de " + titulo, propietario));
    }

    public static UsuarioAutenticado principal(Usuario u) {
        return new UsuarioAutenticado(u.getId(), u.getNombre(), u.getEmail(), u.getContrasenia(), u.getRol(), true);
    }
}
