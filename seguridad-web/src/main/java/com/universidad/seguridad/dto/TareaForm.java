package com.universidad.seguridad.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class TareaForm {

    @NotBlank(message = "El titulo es obligatorio")
    @Size(max = 150)
    private String titulo;

    @Size(max = 500)
    private String descripcion;

    public String getTitulo() { return titulo; }
    public void setTitulo(String titulo) { this.titulo = titulo; }

    public String getDescripcion() { return descripcion; }
    public void setDescripcion(String descripcion) { this.descripcion = descripcion; }
}
