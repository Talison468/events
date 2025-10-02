package com.senai.eventsmanager.repository;

import com.senai.eventsmanager.entity.Evento;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface EventoRepository extends
        JpaRepository<Evento, Long> {
            @Query("SELECT e FROM Evento e WHERE e.dataInicio BETWEEN :inicio AND :fim OR e.dataFinal BETWEEN :inicio AND :fim")
            List<Evento> calendario (LocalDateTime inicio, LocalDateTime fim);

}
