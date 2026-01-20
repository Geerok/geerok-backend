package io.geerok.support.jwt.tokens;

import java.time.LocalDateTime;

public record RefreshToken(
        String jti,
        String token,
        LocalDateTime expiresAt
) implements AuthToken {
    public static RefreshToken create(final String jti, final String token, final LocalDateTime expiresAt) {
        return new RefreshToken(jti, token, expiresAt);
    }
}
