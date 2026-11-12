package com.universidad.seguridad.service;

public class CorreoYaRegistradoException extends RuntimeException {
    public CorreoYaRegistradoException() {
        super("El correo ya esta registrado");
    }
}
