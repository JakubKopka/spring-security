package pl.kopka.springsecurity;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import pl.kopka.springsecurity.model.AppRole;
import pl.kopka.springsecurity.model.AppUser;
import pl.kopka.springsecurity.repo.AppUserRepo;
import pl.kopka.springsecurity.repo.RoleRepo;
import pl.kopka.springsecurity.service.AppUserService;

@Component
public class Init {

    private AppUserService appUserService;
    private AppUserRepo appUserRepo;
    private PasswordEncoder passwordEncoder;
    private RoleRepo roleRepo;

    public Init(AppUserRepo appUserRepo, PasswordEncoder passwordEncoder, AppUserService appUserService, RoleRepo roleRepo) {
        this.passwordEncoder = passwordEncoder;
        this.appUserRepo = appUserRepo;
        this.appUserService = appUserService;
        this.roleRepo = roleRepo;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void initData(){
        AppRole appRoleUser = new AppRole("ROLE_USER");
        roleRepo.save(appRoleUser);

        AppRole appRoleAdmin = new AppRole("ROLE_ADMIN");
        roleRepo.save(appRoleAdmin);

        AppUser appUser = new AppUser("admin", passwordEncoder.encode("admin"),true, "sprngscrt@gmail.com");
        appUser.addRole(appRoleUser);
        appUser.addRole(appRoleAdmin);
        appUserRepo.save(appUser);
    }


}
