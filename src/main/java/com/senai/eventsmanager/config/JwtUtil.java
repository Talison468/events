package com.senai.eventsmanager.config;

import org.springframework.stereotype.Component;
import java.security.Key;
import java.sql.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

    private final String SEGREDO = "umaChaveSuperSecretaDeNoMinimo32Caracteres!";
    private final Key key = Keys.hmacShaKeyFor(SEGREDO.getBytes());

    public String gerarToken(String email){
        return Jwts.builder()
        .setSubject(email) //Eu defino qual o e-mail que será utilizado na autenticação
        .setIssuedAt(new Date(System.currentTimeMillis())) //Quando com data hora minutos e segundos a sessão foi iniciada
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 4)) //Diz quando aquela sessão não será mais válida (4 horas)
        .signWith(key, SignatureAlgorithm.HS256) //Assina e criptografa todo o conteudo com a super senha
        .compact();
    }

    public boolean verificarSeTokenEValido(String token){
        try {
            return true;
        }catch(JwtException | IllegalArgumentException e){
            return false;
        }
    }

    public String extrairEmail(String token){
        return getClaims(token).getBody().getSubject();
    }
    private Jws<Claims> getClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }
}
