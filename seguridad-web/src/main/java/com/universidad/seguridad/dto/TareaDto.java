package com.universidad.seguridad.dto;

import com.universidad.seguridad.model.Tarea;

/** Lo que la API expone de una tarea: sin la entidad Usuario, que trae el hash de la contrasena. */
public record TareaDto(Long id, String titulo, String descripcion, boolean completada) {

    public static TareaDto de(Tarea tarea) {
        return new TareaDto(tarea.getId(), tarea.getTitulo(), tarea.getDescripcion(), tarea.isCompletada());
    }
}
