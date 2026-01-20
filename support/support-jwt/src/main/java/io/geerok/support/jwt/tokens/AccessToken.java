package io.geerok.support.jwt.tokens;

import java.time.LocalDateTime;

public record AccessToken(
        String token,
        LocalDateTime expiresAt
) implements AuthToken {
    public static AccessToken create(final String token, final LocalDateTime expiresAt) {
        return new AccessToken(token, expiresAt);
    }
}
