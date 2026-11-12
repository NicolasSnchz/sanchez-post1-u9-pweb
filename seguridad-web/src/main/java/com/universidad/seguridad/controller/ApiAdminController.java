package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.UsuarioDto;
import com.universidad.seguridad.service.UsuarioService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

// Ruta /api/admin/** de la regla hasRole("ADMIN") de apiFilterChain
@RestController
@RequestMapping("/api/admin")
public class ApiAdminController {

    private final UsuarioService service;

    public ApiAdminController(UsuarioService service) { this.service = service; }

    @GetMapping("/usuarios")
    public List<UsuarioDto> usuarios() {
        return service.listarTodos().stream().map(UsuarioDto::de).toList();
    }
}
