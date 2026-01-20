package io.geerok.support.jwt.tokens;

import java.time.LocalDateTime;

public interface AuthToken {
    String token();
    LocalDateTime expiresAt();
}
