package psf.server.drocsidserver.Services;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import psf.server.drocsidserver.Enums.AccountStatus;
import psf.server.drocsidserver.Models.IpAddressModel;
import psf.server.drocsidserver.Models.LoginModel;
import psf.server.drocsidserver.Models.RegisterModel;
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
    // Verify Fonksiyonu
    public ResponseEntity<String> verifyUser(String token) {
        // Tokenin geçerliliğini kontrol ediyor.
        if (!JwtUtil.isTokenExpired(token)) {
            // Bu kısım ip doğrulaması olursa diye var.
            // Subject de ':' var ise ip doğrulaması olduğunu anlıyor.

            String subject = JwtUtil.extractSubject(token);
            String subjectEmail;
            String ipAddress;

            if (subject.contains(":")) {
                subjectEmail = subject.split(":")[0];
                ipAddress = subject.split(":")[1];
            }else{
                subjectEmail = subject;
                ipAddress = null;
            }

            Optional<User> optionalUser = userRepository.findUserByEmail(subjectEmail);

            if (optionalUser.isPresent()) {
                User user = optionalUser.get();

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

                // Normal verify kısmı
                if (userStatus == AccountStatus.UNVERIFIED) {
                    user.setStatus(AccountStatus.VERIFIED);
                    userRepository.save(user);
                    return ResponseEntity.ok("Account Verified Successfully");
                }else if (userStatus == AccountStatus.VERIFIED) {
                    // Ip doğrulaması mı? Yoksa kayıtlı hesaba tekrardan verify linki
                    // Atılmışmı diye kontrol ediyorum.
                    if (ipAddress != null){
                        IpAddressModel ipAddressModel = new IpAddressModel();
                        ipAddressModel.setIpAddress(ipAddress);
                        ipAddressModel.setUser(user);

                        user.getIpAddresses().add(ipAddressModel);
                        userRepository.save(user);
                        return ResponseEntity.ok("Account Verified Successfully");
                    }

                    return ResponseEntity.ok("User Already Verified");
                }else{
                    // Bu kısım hesap banlanmışsa çalışıyor ve banlı hesabı
                    // Doğrulayamıyoruz.
                    return ResponseEntity.ok("Your Account is Disabled. Please Contact Administrator");
                }
            }

            return ResponseEntity.ok("User Not Found. Try Again or Contact Administrator");
        }

        return ResponseEntity.ok("Your Verification Link is Expired. Please get new Verification Link.");
    }
    // Login Fonksiyonu
    public ResponseEntity<String> loginUser(LoginModel loginModel, String ipAddress) {
        // Kullanıcıyı repositoryden bulma
        // İlk başta Email ile bulmaya çalışıyor bulamaz ise
        // Username ile bulmaya çalışıyor. eğer bulamazise NULL dönüyor.
        Optional<User> optionalUser = Optional.ofNullable(userRepository.findUserByEmail(loginModel.getUsername())
                .orElse(userRepository.findUserByUsername(loginModel.getUsername())
                        .orElse(null)));

        // Kullanıcı gerçekten var ise
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            // User'a kayıtlı ip adreslerinden bir tanesi şuankine eşit ise
            // Userın şifresiyle loginModel deki şifreyi kontrol ediyor
            for (IpAddressModel userIpAdresses: user.getIpAddresses()){
                if (userIpAdresses.getIpAddress().equals(ipAddress)){
                    if (PasswordEncryption.checkPassword(loginModel.getPassword(), user.getPassword())) {
                        return ResponseEntity.ok(JwtUtil.generateToken(loginModel.getUsername(), 999999999));
                    }else{
                        return ResponseEntity.ok("Invalid Password");
                    }
                }
            }

            // Bu kısım kayıtlı ip adreslerinden bir tanesi bile şuankine eşit olmayınca
            // Email hesabına(Bu sefer ip'li doğrulama) tekrardan doğrulama linki gönderiliyor

            String verficationToken = SendVerificationEmail(user.getEmail() + ":" + ipAddress, ipAddress);

            user.setVerificationToken(verficationToken);
            user.setVerificationTokenExpiration(LocalDateTime.now().plusMinutes(10));

            userRepository.save(user);
            return ResponseEntity.ok("New IP Address is Detected. Please Check Your Email");
        }

        return ResponseEntity.ok("Invalid User");
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
