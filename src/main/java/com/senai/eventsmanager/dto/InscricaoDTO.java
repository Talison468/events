package com.senai.eventsmanager.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.senai.eventsmanager.entity.Evento;
import com.senai.eventsmanager.entity.Usuario;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class InscricaoDTO {
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Long id;

    @NotNull(message = "O evento deve ser preenchida")
    private Evento evento;

    @NotNull(message = "O usuario deve ser preenchida")
    private Usuario usuario;
}
