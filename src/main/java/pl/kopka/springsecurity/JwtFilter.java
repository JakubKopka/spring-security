package pl.kopka.springsecurity;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;

public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String authorization = httpServletRequest.getHeader("Authorization");
        UsernamePasswordAuthenticationToken authenticationToken = null;
        try {
            authenticationToken = getUsernamePasswordAuthenticationToken(authorization);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String authorization) throws InvalidKeySpecException, NoSuchAlgorithmException {
        PrivateKey privateKey = getPrivateKey();
        PublicKey publicKey = getPublicKey();
        JWTVerifier jwtVerifier = JWT.require(Algorithm.RSA256((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey)).build();

        DecodedJWT verify = jwtVerifier.verify(authorization.substring(7));
        String name = verify.getClaim("name").asString();
        boolean isAdmin = verify.getClaim("admin").asBoolean();
        String role = "ROLE_USER";
        if (isAdmin)
            role = "ROLE_ADMIN";
        SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(role);
        return new UsernamePasswordAuthenticationToken(name, null, Collections.singleton(simpleGrantedAuthority));
    }

    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKey = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCJtolpQcRSzvEn" +
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

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey key = kf.generatePrivate(keySpec);
        return key;
    }

    private PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKey =
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAibaJaUHEUs7xJ1pQkb8I" +
                        "eXzNuNxR9gea8CEk3fCmMSkoFpsJzFB7v/T5v91HIyo62lKeqeCCDLDez5/ZElLP" +
                        "f6kNGmH68CDaBAaV3wNTmGVDFMYc0NMZ09UJ4pvx+VVWh/3TC29WNF/HrPv2J/ZX" +
                        "njYuZ0Wn1WEDNJHerCEbGUrsyv0s4TqYCfOoxT8nneXZi2KI0JEzXVhV+/ZltcoZ" +
                        "9Gvbftz/Xx3CE1cBzGrn7fL9Wlxw4VDlbGEFCCpiznIhirueattat1PngHIJM4Zf" +
                        "PctQIFHJVOtnN9knIhUsqju+t2KEu23Sxa2HVIi4WGz7Qg6abWD2HrrjNfnQbvoF" +
                        "zQIDAQAB";
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey key = kf.generatePublic(keySpec);
        return key;
    }


}
