package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.TareaForm;
import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.security.UsuarioAutenticado;
import com.universidad.seguridad.service.TareaService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class TareaController {

    private final TareaService service;

    public TareaController(TareaService service) {
        this.service = service;
    }

    @GetMapping("/tareas")
    public String listar(@RequestParam(required = false) String texto,
                         @AuthenticationPrincipal UsuarioAutenticado usuario, Model model) {
        model.addAttribute("tarea", new TareaForm());
        return mostrar(texto, usuario, model);
    }

    @PostMapping("/tareas")
    public String crear(@Valid @ModelAttribute("tarea") TareaForm tarea, BindingResult result,
                        @AuthenticationPrincipal UsuarioAutenticado usuario, Model model) {
        if (result.hasErrors()) {
            return mostrar(null, usuario, model);
        }
        service.crear(tarea.getTitulo(), tarea.getDescripcion(), usuario.getId());
        return "redirect:/tareas";
    }

    @PostMapping("/admin/tareas/{id}/eliminar")
    public String eliminar(@PathVariable Long id) {
        service.eliminar(id);
        return "redirect:/admin";
    }

    private String mostrar(String texto, UsuarioAutenticado usuario, Model model) {
        List<Tarea> tareas;
        if (texto == null || texto.isBlank()) {
            tareas = service.listarDe(usuario.getId());
        } else {
            // el texto viaja como parametro de @Query: nunca se concatena en la consulta
            tareas = usuario.esAdmin() ? service.buscar(texto) : service.buscarDe(texto, usuario.getId());
        }
        model.addAttribute("texto", texto);
        model.addAttribute("tareas", tareas);
        return "tareas/lista";
    }
}
