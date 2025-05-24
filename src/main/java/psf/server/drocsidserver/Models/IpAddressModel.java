package psf.server.drocsidserver.Models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
public class IpAddressModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(unique=true, nullable=false)
    private String ipAddress;

    @Column(nullable = false)
    private LocalDateTime assignedAt;

    @ManyToOne
    @JoinColumn(name = "User_id")
    private User user;
}
