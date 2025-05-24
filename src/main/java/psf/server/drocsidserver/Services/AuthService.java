package psf.server.drocsidserver.Services;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import psf.server.drocsidserver.DTO.LoginModel;
import psf.server.drocsidserver.Enums.AccountStatus;
import psf.server.drocsidserver.Models.IpAddressModel;
import psf.server.drocsidserver.Models.User;

import java.time.LocalDateTime;

@Service
public class AuthService {

    private final UserService userService;
    private final EmailService emailService;

    public AuthService(UserService userService, EmailService emailService) {
        this.userService = userService;
        this.emailService = emailService;
    }

    public ResponseEntity<String> login(LoginModel loginModel, String ipAddress) {
        User user = userService.getUserBySubject(loginModel.getUsername());

        if (user == null)
            return new ResponseEntity<>("User Not Found", HttpStatus.NOT_FOUND);

        for (IpAddressModel userIpAdresses: user.getIpAddresses()){
            if (userIpAdresses.getIpAddress().equals(ipAddress)){
                if (PasswordEncryption.checkPassword(loginModel.getPassword(), user.getPassword())) {
                    return ResponseEntity.ok(JwtUtil.generateToken(loginModel.getUsername(), 999999999));
                }else{
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Password");
                }
            }
        }

        String verficationToken = JwtUtil.generateToken(user.getEmail() + ":" + ipAddress, 10);

        userService.setVerificationToken(verficationToken, user);

        emailService.sendVerificationEmail(user.getEmail(),
                                           verficationToken,
                                           emailService.urlBase(ipAddress));

        return ResponseEntity.ok("New IP Address is Detected. Please Check Your Email");
    }

    //Verify Fonksiyonu
    public ResponseEntity<String> verifyUser(String token, String ipAddress) {
        // Token boş ise uyarı gönderiyorum.
        if (token == null || token.isEmpty())
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Link");

        if (!JwtUtil.isTokenExpired(token)) {
            User user = userService.findUserByToken(token);

            if (user == null)
                return new ResponseEntity<>("User Not Found", HttpStatus.NOT_FOUND);

            // Linkden gelen token ile kullanıcıya kayıtlı olan tokeni
            // Karşılaştırıyorum. Eğer eşit değilse uyarı gönderiyorum.
            if (!user.getVerificationToken().equals(token)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid Verification Link");
            }
            // Kullanıcıya kayıtlı Tokenin sona erme süresini kontrol ediyorum
            // Eğer token sona ermişse uyarı gönderiyorum.
            if (!user.getVerificationTokenExpiration().isBefore(LocalDateTime.now())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is expired. Please Get New Verification Link");
            }

            AccountStatus userStatus = user.getStatus();

            if (userStatus == AccountStatus.UNVERIFIED) {
                user.setStatus(AccountStatus.VERIFIED);

                userService.verifyUserIpAddress(ipAddress, user);

                return ResponseEntity.ok("Account Verified Successfully");
            }else if (userStatus == AccountStatus.VERIFIED) {
                // Ip doğrulaması mı? Yoksa kayıtlı hesaba tekrardan verify linki
                // Atılmışmı diye kontrol ediyorum.
                for (IpAddressModel ipAddressModel : user.getIpAddresses()) {
                    if (ipAddressModel.getIpAddress().equals(ipAddress)) {
                        return ResponseEntity.ok("User Already Verified");
                    }
                }
                userService.verifyUserIpAddress(ipAddress, user);

                return ResponseEntity.ok("Account Verified Successfully");
            }else{
                // Bu kısım hesap banlanmışsa çalışıyor ve banlı hesabı
                // Doğrulayamıyoruz.
                return ResponseEntity.ok("Your Account is Disabled. Please Contact Administrator");
            }
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Link Is Expired");
    }
}
