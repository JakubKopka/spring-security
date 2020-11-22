package pl.kopka.springsecurity.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import pl.kopka.springsecurity.model.VerificationToken;

public interface VerificationTokenRepo extends JpaRepository<VerificationToken, Long> {

    VerificationToken findByToken(String token);
}
