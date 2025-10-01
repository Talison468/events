package com.senai.eventsmanager.controller;

import com.senai.eventsmanager.dto.EventoDTO;
import com.senai.eventsmanager.service.EventoService;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/evento")
public class EventoController {
    @Autowired
    EventoService service;

    // pegar um evento pelo seu id
    @GetMapping("/{id}")
    public EventoDTO findById(@PathVariable("id") Long id){
        return service.findById(id);
    }
    // pegar todos os eventos
    @GetMapping
    public List<EventoDTO> findAll(){
        return service.findAll();
    }
    // salvar um evento
    @PostMapping
    public EventoDTO save(
            @RequestBody @Valid EventoDTO eventoCreateDTO ){
        return service.save(eventoCreateDTO);
    }
    // atualizar um evento
    @PutMapping("/{id}")
    public EventoDTO update(
            @PathVariable("id")Long id,
            @RequestBody EventoDTO eventoCreateDTO){
        return service.update(id,eventoCreateDTO);
    }
    // deletar um evento pelo seu id
    @DeleteMapping("/{id}")
    public void deleteById(@PathVariable("id")Long id){

        service.deleteById(id);
    }


}
