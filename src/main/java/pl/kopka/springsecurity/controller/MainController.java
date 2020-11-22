package pl.kopka.springsecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import pl.kopka.springsecurity.model.AppUser;
import pl.kopka.springsecurity.service.AppUserService;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@Controller
public class MainController {

    private final AppUserService appUserService;

    @Autowired
    public MainController(AppUserService appUserService) {
        this.appUserService = appUserService;
    }

    @GetMapping
    public String home() {
        return "home";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/registration")
    public ModelAndView registration() {
        return new ModelAndView("registration", "user", new AppUser());
    }

    @PostMapping("/registration")
    public String registrationPost(@Valid AppUser appUser, HttpServletRequest request) {
        appUserService.addNewUser(appUser, request);
        return "redirect:/login";
    }

    @GetMapping("/verify-token")
    public String verifyUserToken(@RequestParam String token) {
        appUserService.verifyToken(token, false);
        return "redirect:/login";
    }

    @GetMapping("/user")
    public ModelAndView user() {
        Authentication auth = SecurityContextHolder.getContext()
                .getAuthentication();
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("user");
        modelAndView.addObject("username", auth.getName());
        modelAndView.addObject("roles", auth.getAuthorities());

        return modelAndView;
    }

}
