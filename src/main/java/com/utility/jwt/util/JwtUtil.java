package com.utility.jwt.util;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.function.Function;

@Component
public class JwtUtil {

    private static final String SECRET_KEY = "validate_token_key"; // Use a strong key in production
    private static final int TOKEN_VALIDITY = 3600 * 5;


    private final JwtDecoder jwtDecoder;

    private final JwtEncoder jwtEncoder;

    @Autowired
    public JwtUtil(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
    }


    public String getUserNameFromToken(String token) {
        return getClaimFromToken(token, Jwt::getSubject);
    }

    public <T> T getClaimFromToken(String token, Function<Jwt, T> claimsResolver) {
        final Jwt jwt = decodeToken(token);
        return claimsResolver.apply(jwt);
    }

    private Jwt decodeToken(String token) {
        return jwtDecoder.decode(token);
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String userName = getUserNameFromToken(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        Instant expiration = getExpirationDateFromToken(token);
        return expiration.isBefore(Instant.now());
    }

    private Instant getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Jwt::getExpiresAt);
    }

    public String generateToken(UserDetails userDetails) {
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .subject(userDetails.getUsername())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(TOKEN_VALIDITY))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }
}
