package psf.server.drocsidserver.Models;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegisterModel {
    private String username;
    private String email;
    private String password;
}
