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
        String privateKey = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAtq1bp+nhzwWODCx9" +
                "wV52TOPpMN3T6dGlhM8m/ytVmRKgPIQssvCfAN4nGLLqPNeRgbxEsj2buglD5rp1" +
                "0zIydQIDAQABAkA7bsdlJ/ipa/s9BrSbVupSNcxGc8VgSy74uJTNbAHbXN/dKrc1" +
                "fObj0bxgeG31siNeWZHfznkqgKGPFrbSF/mBAiEA+Okxndbq3g+5s/U/S1KceUwo" +
                "4tqfR6JHIOAQTaW1sEUCIQC74UFDrE7Lw1ewzP78UrWL/jDnN3L/b6XAxOoan/IU" +
                "cQIhAJwKrNUzj4foudVsUOKqhnewXA1jWukwfYDJls7mrJE1AiBdivuprALXZP0m" +
                "JArYqn2FpBvJI0x4bahDYEeG1hf7oQIgO5vD82hyykCKSAO7lbbmLifsEc8nMVLw" +
                "YCg5PbuJEII=";

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey key = kf.generatePrivate(keySpec);
        return key;
    }

    private PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKey =
               "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALatW6fp4c8FjgwsfcFedkzj6TDd0+nR" +
                       "pYTPJv8rVZkSoDyELLLwnwDeJxiy6jzXkYG8RLI9m7oJQ+a6ddMyMnUCAwEAAQ==";
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey key = kf.generatePublic(keySpec);
        return key;
    }


}
