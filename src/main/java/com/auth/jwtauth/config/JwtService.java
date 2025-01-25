package com.auth.jwtauth.config;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY="0f4bf5d0cc18f5a91304b981aa16e23e59b9f77c3a5e90846e007667ad97599b";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); // just for the moment
    }


    //implemet the extractClaim method
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        //FIrst let's get all the claims
        final Claims claims = extractAllClaims(token);
        //extracting any claim
        return claimsResolver.apply(claims);
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
