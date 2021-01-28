package pl.kopka.springsecurity;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Stream;

@Controller
public class BootApiClient {

    @Value("${privateKey}")
    private String privateKey;

    public BootApiClient() throws InvalidKeySpecException, NoSuchAlgorithmException {
        addBooks();
        getBooks();
    }

    private void addBooks() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String jwt = generateJwt(true);
        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + jwt);
        String bookToAdd = "Spring Boot in action - user";
        HttpEntity httpEntity = new HttpEntity(bookToAdd, headers);

        RestTemplate restTemplate = new RestTemplate();
        restTemplate.exchange("http://localhost:8080/api/books",
                HttpMethod.POST,
                httpEntity,
                Void.class);
    }

    private void getBooks() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String jwt = generateJwt(true);
        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + jwt);
        HttpEntity httpEntity = new HttpEntity(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String[]> exchange = restTemplate.exchange("http://localhost:8080/api/books",
                HttpMethod.GET,
                httpEntity,
                String[].class);
        Stream.of(exchange.getBody()).forEach(System.out::println);
    }

    private String generateJwt(boolean isAdmin) throws InvalidKeySpecException, NoSuchAlgorithmException {
        Algorithm algorithm = Algorithm.RSA256(null, (RSAPrivateKey) getPrivateKey());
        return JWT.create().withClaim("admin", isAdmin).sign(algorithm);
    }


    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(keySpec);
    }
}
