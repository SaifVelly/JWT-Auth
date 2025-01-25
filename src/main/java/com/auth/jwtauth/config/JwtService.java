package com.auth.jwtauth.config;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;

@Service
public class JwtService {
    private static final String SECRET_KEY="0f4bf5d0cc18f5a91304b981aa16e23e59b9f77c3a5e90846e007667ad97599b";
    public String extractUsername(String token) {
        return null; // just for the moment
    }


    //extract all the claims
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey()) //Signing key is the secret that verifies the sender of the jwt min it s size is 256
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyByte = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyByte);
    }
}
