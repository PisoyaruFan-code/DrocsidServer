package psf.server.drocsidserver.Services;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import psf.server.drocsidserver.Enums.AccountStatus;
import psf.server.drocsidserver.Models.IpAddressModel;
import psf.server.drocsidserver.DTO.LoginModel;
import psf.server.drocsidserver.DTO.RegisterModel;
import psf.server.drocsidserver.Models.User;
import psf.server.drocsidserver.Repository.UserRepository;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final EmailService emailService;

    public UserService(UserRepository userRepository, EmailService emailService) {
        this.userRepository = userRepository;
        this.emailService = emailService;
    }

    // Sıradan kullanıcıyı kayıt etme fonksiyonu. Ayrıyetten
    // Ip adresi kayıt etdiği için güvenlik artıyor.
    public ResponseEntity<String> createUser(RegisterModel user, String ipAddress) {
        User newUser = new User();

        newUser.setUsername(user.getUsername());
        newUser.setEmail(user.getEmail());
        newUser.setPassword(PasswordEncryption.encryptPassword(user.getPassword()));

        IpAddressModel ipAddressModel = new IpAddressModel();

        ipAddressModel.setIpAddress(ipAddress);
        ipAddressModel.setUser(newUser);
        ipAddressModel.setAssignedAt(LocalDateTime.now());

        newUser.getIpAddresses().add(ipAddressModel);

        String verficationToken = SendVerificationEmail(newUser.getEmail(), ipAddress);

        newUser.setVerificationToken(verficationToken);
        newUser.setVerificationTokenExpiration(LocalDateTime.now().plusMinutes(10));

        userRepository.save(newUser);

        return ResponseEntity.ok("User created successfully, Please check your email");
    }
    public void setVerificationToken(String verficationToken, User user) {
        user.setVerificationToken(verficationToken);
        user.setVerificationTokenExpiration(LocalDateTime.now().plusMinutes(10));

        userRepository.save(user);
    }
    public User getUserBySubject(String subject) {
        // Kullanıcıyı repositoryden bulma
        // İlk başta Email ile bulmaya çalışıyor bulamaz ise
        // Username ile bulmaya çalışıyor. eğer bulamaz ise NULL dönüyor.
        Optional<User> optionalUser = Optional.ofNullable(userRepository.findUserByEmail(subject)
                .orElse(userRepository.findUserByUsername(subject)
                        .orElse(null)));

        return optionalUser.orElse(null);
    }
    public void verifyUserIpAddress(String ipAddress, User user) {
        IpAddressModel ipAddressModel = new IpAddressModel();
        ipAddressModel.setIpAddress(ipAddress);
        ipAddressModel.setAssignedAt(LocalDateTime.now());
        ipAddressModel.setUser(user);

        user.getIpAddresses().add(ipAddressModel);
        userRepository.save(user);
    }
    public User findUserByToken(String token) {
        String subject = JwtUtil.extractSubject(token);
        String subjectEmail;

        if (subject.contains(":")) {
            subjectEmail = subject.split(":")[0];
        }else{
            subjectEmail = subject;
        }

        Optional<User> optionalUser = Optional.ofNullable(userRepository.findUserByEmail(subjectEmail)
                .orElse(userRepository.findUserByUsername(subjectEmail).orElse(null)));

        return optionalUser.orElse(null);

    }
    // Hesap Devre Dışı Bırakma Fonksiyonu
    public void DisableAccount(String token) {
        if(!JwtUtil.isTokenExpired(token)) {
            String subjectEmail = JwtUtil.extractSubject(token);
            Optional<User> optionalUser = userRepository.findUserByEmail(subjectEmail);

            optionalUser.ifPresent(user -> user.setStatus(AccountStatus.DISABLED));
        }
    }
    private String SendVerificationEmail(String email, String ipAddress) {
        // Bu kısım geçici olarak var olacak. NAT loopback sorunu yaşadığım için.
        // Ve arkadaşımla programı kullanabilmek için böyle bir çözüm buldum.
        String urlBase = "78.177.73.106";
        if (Objects.equals(ipAddress, "192.168.1.100"))
            urlBase = "shinypog.ddns.net";

        String verficationToken = JwtUtil.generateToken(email, 10);

        emailService.sendVerificationEmail(email, verficationToken,urlBase);

        return verficationToken;
    }
}
