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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

    private byte[] getFile(String filename) throws IOException {
        return Files.readAllBytes(Paths.get("src/main/resources/" + filename));
    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String authorization) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
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

    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] keyBytes = getFile("private_key.der");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(keySpec);
    }

    private PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] keyBytes = getFile("public_key.der");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(keySpec);
    }


}
