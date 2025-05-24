package psf.server.drocsidserver.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import psf.server.drocsidserver.Models.User;

import java.util.Optional;
import java.util.function.Supplier;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findUserByEmail(String email);

    Optional<User> findUserByUsername(String username);
}
