package com.senai.eventsmanager.entity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import com.senai.eventsmanager.enums.EventoEnum;

@Entity //pra dizer pro spring que isso é uma entidade
@Table(name = "evento")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class Evento {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 150)
    private String nome;

    @Column (nullable = false, length = 500)
    private String descricao;

    @Enumerated(EnumType.ORDINAL)
    @Column(nullable = false)
    private EventoEnum tipo;

    @Column(nullable = false, length = 150)
    private String local;

    @Column(nullable = false)
    private LocalDateTime dataInicio;

    @Column(nullable = false)
    private LocalDateTime dataFinal;

    @Column(nullable = true)
    private String linkEvento;

    @Column(nullable = true)
    private String linkImagem;

    @CreatedDate
    @Column(updatable = false, nullable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(nullable = true)
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "evento")
    private List<Inscricao> inscricoes;

}
