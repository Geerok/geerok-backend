package io.geerok.support.jwt.fixture;

import io.geerok.support.jwt.dto.AccessTokenPayload;

import java.util.List;

public class AccessTokenPayloadTestFixture {
    public static AccessTokenPayload create() {
        return new AccessTokenPayload(
                1L,
                "testUser",
                List.of("ROLE_USER")
        );
    }

    public static AccessTokenPayload create(Long userId, String nickname, List<String> authorities) {
        return new AccessTokenPayload(userId, nickname, authorities);
    }
}
