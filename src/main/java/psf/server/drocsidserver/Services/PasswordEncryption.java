package psf.server.drocsidserver.Services;

import com.password4j.Hash;
import com.password4j.Password;
import org.springframework.stereotype.Service;

@Service
public class PasswordEncryption {
    public static String encryptPassword(String password) {
        Hash hash = Password.hash(password)
                .addRandomSalt()
                .withArgon2();

        return hash.getResult();
    }
    public static boolean checkPassword(String PlainPassword, String HashedPassword) {
        return Password.check(PlainPassword, HashedPassword).withArgon2();
    }
}
