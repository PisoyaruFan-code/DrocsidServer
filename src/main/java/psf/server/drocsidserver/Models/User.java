package psf.server.drocsidserver.Models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import psf.server.drocsidserver.Enums.AccountStatus;
import psf.server.drocsidserver.Enums.AuthorityStatus;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;

@Getter
@Setter
@Entity
@Table(name = "\"User\"")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false)
    private AuthorityStatus authority = AuthorityStatus.USER;

    @Enumerated(EnumType.STRING)
    private AccountStatus status = AccountStatus.UNVERIFIED;

    private String verificationToken;
    private LocalDateTime verificationTokenExpiration;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<IpAddressModel> ipAddresses;

    @ElementCollection
    @CollectionTable(name = "User_friends", joinColumns = @JoinColumn(name = "User_id"))
    @Column(name = "friend_id")
    private List<Long> friends;

    @ElementCollection
    @CollectionTable(name = "User_groups", joinColumns = @JoinColumn(name = "User_id"))
    @Column(name = "group_id")
    private List<Long> groups;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime accountCreatedAt;

    @PrePersist
    public void prePersist() {
        if (accountCreatedAt == null) {
            accountCreatedAt = LocalDateTime.now(ZoneOffset.UTC);
        }
    }
}
