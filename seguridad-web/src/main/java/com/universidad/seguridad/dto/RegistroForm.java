package com.universidad.seguridad.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Datos que acepta el formulario de registro. Es una clase aparte de la entidad Usuario para que
 * nadie pueda enviar id, rol o activo en el POST (mass assignment).
 */
public class RegistroForm {

    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 100, message = "El nombre admite hasta 100 caracteres")
    private String nombre;

    @NotBlank(message = "El correo es obligatorio")
    @Email(message = "Debe ser un correo valido")
    @Size(max = 150)
    private String email;

    // BCrypt solo usa los primeros 72 bytes de la contrasena
    @NotBlank(message = "La contrasena es obligatoria")
    @Size(min = 8, max = 72, message = "La contrasena debe tener entre 8 y 72 caracteres")
    private String contrasenia;

    public String getNombre() { return nombre; }
    public void setNombre(String nombre) { this.nombre = nombre; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getContrasenia() { return contrasenia; }
    public void setContrasenia(String contrasenia) { this.contrasenia = contrasenia; }
}
