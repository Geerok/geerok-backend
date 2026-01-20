package io.geerok.support.jwt;

import io.geerok.core.exception.utils.ExceptionCreator;
import io.geerok.support.jwt.dto.AccessTokenPayload;
import io.geerok.support.jwt.dto.RefreshTokenPayload;
import io.geerok.support.jwt.properties.JwtProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.security.Key;
import java.util.Base64;
import java.util.List;

import static io.geerok.support.jwt.exception.JwtException.*;


@Component
@RequiredArgsConstructor
public class JwtResolver {
    private final JwtProperties jwtProperties;

    private Key accessTokenKey;
    private Key refreshTokenKey;

    private final ObjectMapper objectMapper;

    @PostConstruct
    public void init() {
        byte[] accessTokenBytes = Base64.getDecoder().decode(jwtProperties.getAccessToken().getSecretKey());
        accessTokenKey = Keys.hmacShaKeyFor(accessTokenBytes);

        byte[] refreshTokenBytes = Base64.getDecoder().decode(jwtProperties.getRefreshToken().getSecretKey());
        refreshTokenKey = Keys.hmacShaKeyFor(refreshTokenBytes);
    }

    public AccessTokenPayload getPayloadFromAccessToken(String token) {
        try {
            if (token == null) throw ExceptionCreator.create(ACCESS_TOKEN_NOT_FOUND);

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(accessTokenKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            List<String> authorities = objectMapper.convertValue(
                    claims.get("authorities", List.class),
                    new TypeReference<>() {}
            );

            return new AccessTokenPayload(
                    claims.get("user_id", Long.class),
                    claims.get("nickname", String.class),
                    authorities
            );
        } catch (SecurityException | UnsupportedJwtException | SignatureException | MalformedJwtException | DecodingException e) {
            throw ExceptionCreator.create(ACCESS_TOKEN_INVALID, "AccessToken: " + token);
        } catch (ExpiredJwtException e) {
            throw ExceptionCreator.create(ACCESS_TOKEN_EXPIRED, "AccessToken: " + token);
        }
    }

    public RefreshTokenPayload getPayloadFromRefreshToken(String token) {
        try {
            if (token == null) throw ExceptionCreator.create(REFRESH_TOKEN_NOT_FOUND);

            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(refreshTokenKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return new RefreshTokenPayload(claims.get("user_id", Long.class));
        } catch (SecurityException | UnsupportedJwtException | SignatureException | MalformedJwtException | DecodingException e) {
            throw ExceptionCreator.create(REFRESH_TOKEN_INVALID, "RefreshToken: " + token);
        } catch (ExpiredJwtException e) {
            throw ExceptionCreator.create(REFRESH_TOKEN_EXPIRED, "RefreshToken: " + token);
        }
    }
}
