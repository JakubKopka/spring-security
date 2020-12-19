package pl.kopka.springsecurity;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
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
        String rsaPrivateKey =
                "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAtq1bp+nhzwWODCx9" +
                        "wV52TOPpMN3T6dGlhM8m/ytVmRKgPIQssvCfAN4nGLLqPNeRgbxEsj2buglD5rp1" +
                        "0zIydQIDAQABAkA7bsdlJ/ipa/s9BrSbVupSNcxGc8VgSy74uJTNbAHbXN/dKrc1" +
                        "fObj0bxgeG31siNeWZHfznkqgKGPFrbSF/mBAiEA+Okxndbq3g+5s/U/S1KceUwo" +
                        "4tqfR6JHIOAQTaW1sEUCIQC74UFDrE7Lw1ewzP78UrWL/jDnN3L/b6XAxOoan/IU" +
                        "cQIhAJwKrNUzj4foudVsUOKqhnewXA1jWukwfYDJls7mrJE1AiBdivuprALXZP0m" +
                        "JArYqn2FpBvJI0x4bahDYEeG1hf7oQIgO5vD82hyykCKSAO7lbbmLifsEc8nMVLw" +
                        "YCg5PbuJEII=";

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(keySpec);
    }
}
