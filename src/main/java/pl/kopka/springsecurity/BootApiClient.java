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
                "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCJtolpQcRSzvEn" +
                "WlCRvwh5fM243FH2B5rwISTd8KYxKSgWmwnMUHu/9Pm/3UcjKjraUp6p4IIMsN7P" +
                "n9kSUs9/qQ0aYfrwINoEBpXfA1OYZUMUxhzQ0xnT1Qnim/H5VVaH/dMLb1Y0X8es" +
                "+/Yn9leeNi5nRafVYQM0kd6sIRsZSuzK/SzhOpgJ86jFPyed5dmLYojQkTNdWFX7" +
                "9mW1yhn0a9t+3P9fHcITVwHMauft8v1aXHDhUOVsYQUIKmLOciGKu55q21q3U+eA" +
                "cgkzhl89y1AgUclU62c32SciFSyqO763YoS7bdLFrYdUiLhYbPtCDpptYPYeuuM1" +
                "+dBu+gXNAgMBAAECggEATEeEk33vTeL8psya5jAHdKuRk/zNlVafFrV1I04h8AcZ" +
                "AnR8F+TYtvntwL3DopHIqZer9PK7dmYd9KlY5pJiBxdPf7aX9ZxsxmATccT47+ff" +
                "IUmfOnhDzRcq849nl7ESTh9lX+cau8X15zZlIbuMysC+MUve7A1hZiQKUBPCW95U" +
                "0EdeTIIEZzT6Z94rj5rExBnfz2JxADh6dRETcoaqW+iLw5tzMxisNOTZLBc3swVq" +
                "KIg7nQCj+OhPymNJZS6aKt9gebUahff4gjW8PvBauj84rSY/19EmPHGY3umk2ykW" +
                "T5a8g34rX0xS/mYHC4mO0rV7mcSjllDqPuqKzKHBTQKBgQDoTsu22K25vpVcd6AK" +
                "ZYly4EMNTVcV1nd7dZTA9Z8ZF1hElWSxylqkJzlU5NF1e93nDzM6agvJQeCBSJHt" +
                "FR5c0Omd5njct+fEKHaEXpyU4AQcIinyXhDaTTyQeJvnM460N9rsQvUzfTI6UdJu" +
                "ejUoWSPCHxAnC+NnwfGF+tLwWwKBgQCXwgPmbm/9jEYMZ6A0RnSzPApDYC0SvU2t" +
                "dTZ1qpEDdGjCtjhwrs6BA93+ejCMP20N5uQLVVOA7ief3EMRIscq1m1St2OKlAkv" +
                "nsUtyhHiYbauMmQy91OFyiNBDWnCHJXNBRNq9FSNKbGxJV+LRAL1W5GrGZIqac/0" +
                "IXs/+Ra69wKBgQDV5KchBcR/P4FakDJlIDQ7900FlG5Yhw2gORTrzbvdaGc3Tq5W" +
                "HND0T8Ez7zMEjzYzpwUuBbIwbl197AmgV0+Lejd/0VL7NsFJFVB6dHqLgO+Hz9T7" +
                "eazeszrOcp5pdEkymjMSUlxeOinjFK9CVXdYXSrVc7B1ozaQtDvjdpx9/QKBgBhS" +
                "IJviYRJKU8OTK+qUzAkZey+XD0IsknFVEphC8KCUHGHwIBV2/mNQwlgRLwya8ZhD" +
                "w5JJZ2uHP1RwUVNCtpaX7MdP2qUP2nUGReVzt/AG5ub97m74kisj3QiE5MkWGa/U" +
                "u2rto0tIPlD8g1ZnXO4DcdHw9CrV8FzYrM7w1YK7AoGBAJ5aBFFb4i57KgAdgkTa" +
                "8R2Z91FdN2pwdlps6wX/kbuF+TU2b07hCU4y6tjYmWtLDg6vPXl2+B77t8J7k5zW" +
                "xErI7ymZFh+CJqg/vK78XCHe9zEx65kwK9jrrOsYJrYdT0EZd21h+dMTFeJT3qrZ" +
                "5LZetKjs3SzwNiyZQwcazbVj";

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey key = kf.generatePrivate(keySpec);

        return key;
    }
}
