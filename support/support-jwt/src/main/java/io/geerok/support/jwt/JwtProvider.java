package io.geerok.support.jwt;

import io.geerok.support.jwt.dto.AccessTokenPayload;
import io.geerok.support.jwt.properties.JwtProperties;
import io.geerok.support.jwt.tokens.AccessToken;
import io.geerok.support.jwt.tokens.RefreshToken;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtProvider {
    private final JwtProperties jwtProperties;
    private Key accessTokenKey;
    private Key refreshTokenKey;

    @PostConstruct
    public void init() {
        byte[] accessTokenBytes = Base64.getDecoder().decode(jwtProperties.getAccessToken().getSecretKey());
        accessTokenKey = Keys.hmacShaKeyFor(accessTokenBytes);

        byte[] refreshTokenBytes = Base64.getDecoder().decode(jwtProperties.getRefreshToken().getSecretKey());
        refreshTokenKey = Keys.hmacShaKeyFor(refreshTokenBytes);
    }

    public AccessToken generateAccessToken(AccessTokenPayload payload) {
        ZoneId zoneId = ZoneId.of("Asia/Seoul");
        LocalDateTime now = LocalDateTime.now(zoneId);
        LocalDateTime expiresAt = now.plusSeconds(jwtProperties.getAccessToken().getExpiresIn());

        Date expiresAtInDate = Date.from(expiresAt.atZone(zoneId).toInstant());

        String token = Jwts.builder()
                .claim("user_id", payload.userId())
                .claim("nickname", payload.nickname())
                .claim("authorities",payload.authorities())
                .setExpiration(expiresAtInDate)
                .signWith(accessTokenKey, SignatureAlgorithm.HS256)
                .compact();

        return AccessToken.create(token, expiresAt);
    }

    public RefreshToken generateRefreshToken(Long userId) {
        ZoneId zoneId = ZoneId.of("Asia/Seoul");
        LocalDateTime now = LocalDateTime.now(zoneId);
        LocalDateTime expiresAt = now.plusSeconds(jwtProperties.getRefreshToken().getExpiresIn());

        Date expiresAtInDate = Date.from(expiresAt.atZone(zoneId).toInstant());
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
                .claim("jti", jti)
                .claim("user_id", userId)
                .setExpiration(expiresAtInDate)
                .signWith(refreshTokenKey, SignatureAlgorithm.HS256)
                .compact();
        log.debug("RefreshToken Generated for user {}: {}", userId, token);

        return RefreshToken.create(jti, token, expiresAt);
    }
}
