package com.senai.eventsmanager.config;

import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
                /*Pegar o Header o procurar o campo Authorization dentro dele*/
        String authHeader = request.getHeader("Authorization");

        if(authHeader != null && authHeader.startsWith("Bearer ")){
            /*Extrair token de acesso */
            String token = authHeader.substring(7);

            /*Extrair o nome usuário */
            String email = jwtUtil.extrairEmail(token);
            /*Verifica se realmente existe um e-mail, e se ainda não está autenticado */
            if(email != null && SecurityContextHolder.getContext().getAuthentication() == null){
                    //Cria uma sessão de autenticação
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(token, null, null);

                    //Salvar a sessão recem criada
                    SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
