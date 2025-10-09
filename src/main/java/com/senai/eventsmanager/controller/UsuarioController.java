package com.senai.eventsmanager.controller;

import com.senai.eventsmanager.dto.UsuarioDTO;
import com.senai.eventsmanager.enums.UsuarioEnum;
import com.senai.eventsmanager.service.UsuarioService;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/v1/usuario")
public class UsuarioController {

    @Autowired
    private UsuarioService service;

    @GetMapping("/filtro/{tipo}")
    public List<UsuarioDTO> filtro(@PathVariable("tipo") UsuarioEnum tipo){
        return service.findByTipo(tipo);
    }
    @GetMapping("/{id}")
    public UsuarioDTO findById(@PathVariable("id") Long id){
        return service.findById(id);
    }
    
    @GetMapping
    public List<UsuarioDTO> findAll(){
        return service.findAll();
    }
    
    @PostMapping
    public UsuarioDTO save(
            @RequestBody @Valid UsuarioDTO usuarioCreateDTO ){
        return service.save(usuarioCreateDTO);
    }
    
    @PutMapping("/{id}")
    public UsuarioDTO update(
            @PathVariable("id")Long id,
            @RequestBody UsuarioDTO usuarioCreateDTO){
        return service.update(id,usuarioCreateDTO);
    }
    
    @DeleteMapping("/{id}")
    public void deleteById(@PathVariable("id")Long id){
        service.deleteById(id);
    } 
}
