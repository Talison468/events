package com.senai.eventsmanager.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.senai.eventsmanager.config.JwtUtil;
import com.senai.eventsmanager.dto.AuthDTO;
import com.senai.eventsmanager.service.UsuarioService;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private UsuarioService service;
    
    @Autowired
    private JwtUtil jwtUtil;
    
    @PostMapping("/login")
    public  ResponseEntity<Map<String, String>> login(@RequestBody @Valid AuthDTO dto) {
        String email = dto.getEmail();
        String senha = dto.getSenha();

        if(service.autenticar(email, senha)){
                String token = jwtUtil.gerarToken(email);
                return ResponseEntity.ok(Map.of("token", token));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(Map.of("error", "Credenciais inválidas"));
    }
}
