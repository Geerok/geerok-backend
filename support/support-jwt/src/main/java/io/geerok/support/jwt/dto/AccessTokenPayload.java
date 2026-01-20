package io.geerok.support.jwt.dto;

import java.util.List;

public record AccessTokenPayload(
        Long userId,
        String nickname,
        List<String> authorities
) {

}
