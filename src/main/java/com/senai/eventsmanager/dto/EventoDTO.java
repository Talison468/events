package com.senai.eventsmanager.dto;

import java.time.LocalDateTime;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.senai.eventsmanager.enums.EventoEnum;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class EventoDTO {

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Long id;

    @NotBlank(message = "O nome deve ser preenchido")
    @Size(max = 150, message = "O nome deve ter no máximo 150 caracteres")
    private String nome;

    @NotBlank(message = "A descrição deve ser preenchido")
    @Size(max = 150, message = "A descrição deve ter no máximo 500 caracteres")
    private String descricao;

    @NotNull(message = "O tipo do evento deve ser preenchido")
    private EventoEnum tipo;

    @NotBlank(message = "O local deve ser preenchido")
    @Size(max = 150, message = "O local deve ter no máximo 150 caracteres")
    private String local;

    @NotNull(message = "A data de inicio deve ser preenchida")
    @JsonFormat(pattern =  "dd/MM/yyyy HH:mm")
    private LocalDateTime dataInicio;

    @NotNull(message = "A data de final deve ser preenchida")
    @JsonFormat(pattern = "dd/MM/yyyy HH:mm")
    private LocalDateTime dataFinal;


    private String linkEvento;
    private String linkImagem;

}