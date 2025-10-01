package com.senai.eventsmanager.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import java.util.Date;
import org.hibernate.validator.constraints.br.CPF;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.senai.eventsmanager.enums.UsuarioEnum;
import com.senai.eventsmanager.validation.DeveTerNumeros;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UsuarioDTO {
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private Long id;

    @NotBlank(message = "O email deve ser preenchido")
    @Email (message = "Email inválido")
    private String email;

    @NotBlank(message = "A senha deve ser preenchido")
    @DeveTerNumeros
    private String senha;

    @NotBlank(message = "O nome deve ser preenchido")
    @Size(max = 150, min = 3, message = "O nome deve ter no máximo 150 caracteres")
    private String nome;

    @NotBlank(message = "O CPF deve ser preenchido")
    @CPF
    private String cpf;

    @NotBlank(message = "O telefone deve ser preenchido")
    @Size(max = 15, message = "O telefone deve ter no máximo 15 caracteres")
    private String telefone;

    @NotNull(message = "O tipo do usuario deve ser preenchido")
    private UsuarioEnum tipo;

    @NotNull(message = "A data de nascimento deve ser preenchida")
    @JsonFormat(pattern = "dd/MM/yyyy")
    private Date dataNascimento;
}
