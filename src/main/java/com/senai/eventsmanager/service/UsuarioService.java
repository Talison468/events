package com.senai.eventsmanager.service;

import com.senai.eventsmanager.dto.UsuarioDTO;
import com.senai.eventsmanager.entity.Usuario;
import com.senai.eventsmanager.repository.UsuarioRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class UsuarioService {
    @Autowired
    UsuarioRepository repository;

    public UsuarioDTO findById(Long id) {
        Usuario usuario = repository.findById(id).orElseThrow();
        return toDto(usuario);
    }
    public UsuarioDTO save(UsuarioDTO usuarioDto) {
        Usuario usuario = toEntity(usuarioDto);
        usuario.setCreatedAt(LocalDateTime.now());
        usuario.setUpdatedAt(LocalDateTime.now());
        usuario = repository.save(usuario);
        return toDto(usuario);
     }
    public UsuarioDTO update(Long id, UsuarioDTO usuarioDto) {
        Usuario usuario = toEntity(usuarioDto);
        usuario.setId(id);
        usuario = repository.save(usuario);
        return toDto(usuario);
    }
    public void deleteById(Long id) {
        repository.deleteById(id);
    }
    public List<UsuarioDTO> findAll() {
        List<Usuario> usuarios = repository.findAll();
        List<UsuarioDTO> usuariosDto = new ArrayList<>();
        for (Usuario usuario : usuarios) {
            usuariosDto.add(toDto(usuario));
        }
        return usuariosDto;
    }
    public UsuarioDTO toDto(Usuario usuario) {
        UsuarioDTO DTO = new UsuarioDTO();
        BeanUtils.copyProperties(usuario, DTO);
        return DTO;
    }

    public Usuario toEntity(UsuarioDTO DTO){
        Usuario usuario = new Usuario();
        BeanUtils.copyProperties(DTO, usuario);
        return usuario;
    }
}
