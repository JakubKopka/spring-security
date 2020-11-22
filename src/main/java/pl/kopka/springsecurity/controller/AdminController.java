package pl.kopka.springsecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import pl.kopka.springsecurity.service.AppUserService;

@Controller
@RequestMapping(value = "/admin")
public class AdminController {

    private final AppUserService appUserService;

    @Autowired
    public AdminController(AppUserService appUserService) {
        this.appUserService = appUserService;
    }

    @GetMapping
    public String admin(){
        return "admin";
    }

    @GetMapping("/verify-token")
    public String verifyUserTokenAdmin(@RequestParam String token){
        appUserService.verifyToken(token, true);
        return "redirect:/login";
    }
}
