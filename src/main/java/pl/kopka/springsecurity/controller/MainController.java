package pl.kopka.springsecurity.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@Controller
@RestController
public class MainController {

    @GetMapping
    public String home(Principal principal) {
        try {
            return "Cześć " + principal.getName();
        } catch (NullPointerException ex) {
            return "Cześć nieznajomy";
        }
    }

    @GetMapping("/admin")
    public String admin(Principal principal) {
        return "Cześć admin " + principal.getName();
    }

    @GetMapping("/user")
    public String user(Principal principal) {
        return "Cześć user " + principal.getName();
    }

    @GetMapping("/papa")
    public String logout() {
        return "Papa";
    }

}
