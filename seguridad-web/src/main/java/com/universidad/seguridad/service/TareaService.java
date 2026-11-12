package com.universidad.seguridad.service;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class TareaService {
    private final TareaRepository repo;
    private final UsuarioRepository usuarios;

    public TareaService(TareaRepository repo, UsuarioRepository usuarios) {
        this.repo = repo;
        this.usuarios = usuarios;
    }

    // ADMIN ve las de cualquiera; USER solo las suyas. principal.id existe en las dos
    // superficies porque ambas autentican con un UsuarioAutenticado
    @PreAuthorize("hasRole('ADMIN') or #usuarioId == authentication.principal.id")
    public List<Tarea> listarDe(Long usuarioId) {
        return repo.findByPropietarioId(usuarioId);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public List<Tarea> listarTodas() {
        return repo.findAll();
    }

    // Busqueda global, solo para ADMIN
    @PreAuthorize("hasRole('ADMIN')")
    public List<Tarea> buscar(String texto) {
        return repo.buscarPorTitulo(texto); // @Query parametrizado: seguro
    }

    // Busqueda dentro de las tareas propias
    @PreAuthorize("#usuarioId == authentication.principal.id")
    public List<Tarea> buscarDe(String texto, Long usuarioId) {
        return repo.buscarPorTituloDe(texto, usuarioId); // @Query parametrizado: seguro
    }

    @Transactional
    @PreAuthorize("#usuarioId == authentication.principal.id")
    public Tarea crear(String titulo, String descripcion, Long usuarioId) {
        return repo.save(new Tarea(titulo, descripcion, usuarios.getReferenceById(usuarioId)));
    }

    @Transactional
    @PreAuthorize("hasRole('ADMIN')")
    public void eliminar(Long tareaId) {
        repo.deleteById(tareaId);
    }
}
