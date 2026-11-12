package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.RegistroForm;
import com.universidad.seguridad.security.UsuarioAutenticado;
import com.universidad.seguridad.service.CorreoYaRegistradoException;
import com.universidad.seguridad.service.TareaService;
import com.universidad.seguridad.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AuthController {

    private final UsuarioService service;
    private final TareaService tareas;

    public AuthController(UsuarioService service, TareaService tareas) {
        this.service = service;
        this.tareas = tareas;
    }

    @GetMapping("/")
    public String inicio() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    public String mostrarLogin() {
        return "auth/login";
    }

    @GetMapping("/registro")
    public String mostrarRegistro(Model model) {
        model.addAttribute("usuario", new RegistroForm());
        return "auth/registro";
    }

    @PostMapping("/registro")
    public String registrar(@Valid @ModelAttribute("usuario") RegistroForm usuario, BindingResult result) {
        if (result.hasErrors()) {
            return "auth/registro";
        }
        try {
            service.registrar(usuario.getNombre(), usuario.getEmail(), usuario.getContrasenia());
            return "redirect:/login?registrado";
        } catch (CorreoYaRegistradoException e) {
            result.rejectValue("email", "error.email", e.getMessage());
            return "auth/registro";
        }
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, @AuthenticationPrincipal UsuarioAutenticado usuario) {
        // El nombre (texto libre que escribio el usuario) es el campo donde se prueba el XSS
        model.addAttribute("usuario", usuario.getNombre());
        model.addAttribute("email", usuario.getUsername());
        model.addAttribute("roles", usuario.getAuthorities());
        return "dashboard";
    }

    @GetMapping("/admin")
    public String adminPanel(Model model) {
        model.addAttribute("usuarios", service.listarTodos());
        model.addAttribute("tareas", tareas.listarTodas());
        return "admin/panel";
    }
}
