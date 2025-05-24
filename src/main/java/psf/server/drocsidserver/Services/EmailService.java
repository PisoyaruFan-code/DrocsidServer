package psf.server.drocsidserver.Services;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendVerificationEmail(String toEmail, String token, String urlBase) {
        String verificationUrl =  "http://" + urlBase + ":8080/api/userLogin/verify?token=" + token;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom("lolultrahasagi@gmail.com");
        message.setTo(toEmail);
        message.setSubject("Hesap Doğrulama");
        message.setText("Hesabınızı doğrulamak için aşağıdaki bağlantıya tıklayın:\n" + verificationUrl);

        mailSender.send(message);
    }
}