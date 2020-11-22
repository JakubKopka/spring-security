package pl.kopka.springsecurity.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import pl.kopka.springsecurity.model.AppUser;
import pl.kopka.springsecurity.model.AppRole;
import pl.kopka.springsecurity.model.VerificationToken;
import pl.kopka.springsecurity.repo.AppUserRepo;
import pl.kopka.springsecurity.repo.RoleRepo;
import pl.kopka.springsecurity.repo.VerificationTokenRepo;

import javax.servlet.http.HttpServletRequest;
import java.util.UUID;

@Service
public class AppUserService {

    Logger logger = LoggerFactory.getLogger(MailSenderService.class);

    private final AppUserRepo appUserRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;
    private final MailSenderService mailSenderService;
    private final VerificationTokenRepo verificationTokenRepo;

    @Autowired
    public AppUserService(AppUserRepo appUserRepo, RoleRepo roleRepo, PasswordEncoder passwordEncoder, MailSenderService mailSenderService, VerificationTokenRepo verificationTokenRepo) {
        this.appUserRepo = appUserRepo;
        this.roleRepo = roleRepo;
        this.passwordEncoder = passwordEncoder;
        this.mailSenderService = mailSenderService;
        this.verificationTokenRepo = verificationTokenRepo;
    }


    public void addNewUser(AppUser appUser, HttpServletRequest request) {
        AppRole appRoleUser = new AppRole("ROLE_USER");
        roleRepo.save(appRoleUser);
        appUser.addRole(appRoleUser);

        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        appUserRepo.save(appUser);

        String tokenUser = UUID.randomUUID().toString();

        VerificationToken vtUser = new VerificationToken(tokenUser, appUser);
        verificationTokenRepo.save(vtUser);

        String url = createVerificationUrl(false, tokenUser, request);
        mailSenderService.sendVerificationMailToUser(appUser, url);

        int rememberMeValue = Integer.parseInt(appUser.getRememberMeValue());
        switch (rememberMeValue){
            case 7:

                break;
            case 21:

                break;
            case 28:

                break;
            default:
                logger.error("Bad value of rememberMeValue!");
                break;
        }
    }

    public void verifyToken(String token, boolean isAdminToken) {
        VerificationToken verificationToken = verificationTokenRepo.findByToken(token);
        AppUser appUser = verificationToken.getAppUser();
        if (isAdminToken) {
            AppRole appRoleAdmin = new AppRole("ROLE_ADMIN");
            roleRepo.save(appRoleAdmin);
            appUser.addRole(appRoleAdmin);
        } else {
            appUser.setEnabled(true);
        }
        appUserRepo.save(appUser);
        verificationTokenRepo.delete(verificationToken);
    }

    public String createVerificationUrl(boolean isAdminToken, String token, HttpServletRequest request) {
        String host = request.getServerName();
        int port = request.getServerPort();
        String path = request.getContextPath();
        if (isAdminToken) {
            path += "/admin";
        }
        path += "/verify-token?token=" + token;
        return "http://" + host + ":" + port + path;
    }
}
