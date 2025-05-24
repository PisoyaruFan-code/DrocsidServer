package psf.server.drocsidserver.DTO;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterModel {
    @NotBlank(message = "Username can't be blank")
    private String username;

    @NotBlank(message = "Email can't be blank")
    @Email(message = "Email is not valid")
    private String email;

    @NotBlank(message = "Password can't be blank")
    private String password;
}
