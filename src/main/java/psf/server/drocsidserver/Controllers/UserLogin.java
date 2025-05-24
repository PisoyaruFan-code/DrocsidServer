package psf.server.drocsidserver.Controllers;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import psf.server.drocsidserver.Models.LoginModel;
import psf.server.drocsidserver.Models.RegisterModel;
import psf.server.drocsidserver.Services.JwtUtil;
import psf.server.drocsidserver.Services.UserService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/userLogin")
public class UserLogin {
    private final List<String> Ips = new ArrayList<>();
    private final Map<String, Integer> LoginAttempts = new HashMap<>();
    private final List<String> restrictedIps = new ArrayList<>();

    private final UserService userService;

    public UserLogin(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterModel registerModel, HttpServletRequest request) {
        String ip = getClientIp(request);
        Ips.add(ip);

        return userService.createUser(registerModel, ip);
    }
    @GetMapping("/verify")
    public ResponseEntity<String> verify(@RequestParam String token, HttpServletRequest request) {
        return userService.verifyUser(token);
    }
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginModel LoginModel, HttpServletRequest request) {
        for (String ip : restrictedIps) {
            if (JwtUtil.extractSubject(ip).equals(getClientIp(request))) {
                if (JwtUtil.isTokenExpired(ip)) {
                    restrictedIps.remove(ip);
                }
            }
        }

        if (Ips.contains(getClientIp(request))) {
            if (LoginAttempts.get(getClientIp(request)) != null && LoginAttempts.get(getClientIp(request)) > 3) {
                restrictedIps.add(JwtUtil.generateToken(getClientIp(request), 15));
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            if (LoginAttempts.containsKey(getClientIp(request))) {
                LoginAttempts.put(getClientIp(request), LoginAttempts.get(getClientIp(request))+1);
            }else {
                LoginAttempts.put(getClientIp(request), 1);
            }
            return userService.loginUser(LoginModel, getClientIp(request));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
    private String getClientIp(HttpServletRequest request) {
        String clientIp;

        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null) {
            clientIp = forwardedFor.split(",")[0];
        } else {
            clientIp = request.getRemoteAddr();
        }

        return clientIp;
    }
}
