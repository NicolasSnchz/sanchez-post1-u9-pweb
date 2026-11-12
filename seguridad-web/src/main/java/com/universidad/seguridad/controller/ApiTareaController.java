package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.TareaDto;
import com.universidad.seguridad.security.UsuarioAutenticado;
import com.universidad.seguridad.service.TareaService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/tareas")
public class ApiTareaController {

    private final TareaService service;

    public ApiTareaController(TareaService service) { this.service = service; }

    @GetMapping
    public List<TareaDto> misTareas(@AuthenticationPrincipal UsuarioAutenticado usuario) {
        // El principal llega poblado por JwtAuthFilter, del mismo tipo que llegaria por sesion:
        // el servicio y su @PreAuthorize no necesitan saber con que mecanismo entro el usuario
        return service.listarDe(usuario.getId()).stream().map(TareaDto::de).toList();
    }
}
