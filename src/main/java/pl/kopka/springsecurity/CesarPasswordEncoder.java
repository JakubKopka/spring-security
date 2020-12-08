package pl.kopka.springsecurity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class CesarPasswordEncoder implements PasswordEncoder {

    @Value("${shift}")
    private int shift;

    @Override
    public String encode(CharSequence charSequence) {
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < charSequence.length(); i++) {
            char x = charSequence.charAt(i);
            if(Character.isUpperCase(x)){
                password.append((char) (((int) x + shift - 65) % 26 + 65));
            }else{
                password.append((char) (((int) x + shift - 97) % 26 + 97));
            }
        }
        return password.toString();
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encode(rawPassword).equals(encodedPassword);
    }
}
