package com.senai.eventsmanager.service;

import com.senai.eventsmanager.dto.InscricaoDTO;
import com.senai.eventsmanager.entity.Inscricao;
import com.senai.eventsmanager.repository.InscricaoRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;

@Service
public class InscricaoService {
    @Autowired
    InscricaoRepository repository;
    public InscricaoDTO findById(Long id){
        Inscricao inscricao = repository.findById(id).orElseThrow();
        InscricaoDTO inscricaoDto = toDto(inscricao);
        return inscricaoDto;
    }
    public InscricaoDTO save(InscricaoDTO inscricaoDto){
        Inscricao inscricao = toEntity(inscricaoDto);
        inscricao = repository.save(inscricao);
        return toDto(inscricao);
    }
    public InscricaoDTO update(Long id, InscricaoDTO inscricaoDto){
        Inscricao inscricao = toEntity(inscricaoDto);
        inscricao.setId(id);
        inscricao = repository.save(inscricao);
        return toDto(inscricao);
    }
    public void deleteById(Long id){
        repository.deleteById(id);
    }
    public List<InscricaoDTO> findAll(){
        List<Inscricao> inscricoes = repository.findAll();
        List<InscricaoDTO> inscricoesDto = new ArrayList<>();
        for(Inscricao inscricao : inscricoes){
            inscricoesDto.add(toDto(inscricao));
        }
        return inscricoesDto;
    }

    public InscricaoDTO toDto(Inscricao inscricao){
        InscricaoDTO inscricaoDto = new InscricaoDTO();
        BeanUtils.copyProperties(inscricao, inscricaoDto);
        return inscricaoDto;
    }

    public Inscricao toEntity(InscricaoDTO DTO){
        Inscricao inscricao = new Inscricao();
        BeanUtils.copyProperties(DTO, inscricao);
        return inscricao;
    }
}
