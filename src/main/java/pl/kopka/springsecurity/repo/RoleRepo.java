package pl.kopka.springsecurity.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pl.kopka.springsecurity.model.AppRole;

@Repository
public interface RoleRepo extends JpaRepository<AppRole, Long> {
}
