package pl.kopka.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

@SpringBootApplication
public class SpringSecurityApplication {

    @Autowired
    CesarPasswordEncoder cesarPasswordEncoder;

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }


    @EventListener(ApplicationReadyEvent.class)
    public void test(){
        System.out.println(cesarPasswordEncoder.encode("#Test@123"));
        System.out.println(cesarPasswordEncoder.matches("#Test@123", cesarPasswordEncoder.encode("#Test@123")));
    }

}
