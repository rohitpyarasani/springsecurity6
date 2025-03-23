package com.utility.jwt.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.function.Function;

@Component
public class JwtUtil {

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
                .issuer("self")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(TOKEN_VALIDITY))
                .build();

        var encoderParameters = JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claimsSet);
        return this.jwtEncoder.encode(encoderParameters).getTokenValue();
    }
}
