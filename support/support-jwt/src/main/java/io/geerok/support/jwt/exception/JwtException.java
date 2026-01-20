package io.geerok.support.jwt.exception;

import io.geerok.core.exception.UnauthorizedException;
import io.geerok.core.exception.utils.ExceptionInterface;
import lombok.Getter;

@Getter
public enum JwtException implements ExceptionInterface {
    ACCESS_TOKEN_NOT_FOUND("JWT-901", "로그인이 필요한 서비스입니다. 로그인 후 이용해 주세요.", UnauthorizedException.class),
    ACCESS_TOKEN_INVALID("JWT-902", "로그인 세션이 만료되었습니다. 다시 로그인해 주세요.", UnauthorizedException.class),
    ACCESS_TOKEN_EXPIRED("JWT-903", "로그인 세션이 만료되었습니다. 다시 로그인해 주세요.", UnauthorizedException.class),

    REFRESH_TOKEN_NOT_FOUND("JWT-904", "로그인이 필요한 서비스입니다. 로그인 후 이용해 주세요.", UnauthorizedException.class),
    REFRESH_TOKEN_INVALID("JWT-905", "로그인 세션이 만료되었습니다. 다시 로그인해 주세요.", UnauthorizedException.class),
    REFRESH_TOKEN_EXPIRED("JWT-906", "로그인 세션이 만료되었습니다. 다시 로그인해 주세요.", UnauthorizedException.class),
    ;

    private final String errorCode;
    private final String message;
    private final Class<?> aClass;

    JwtException(String errorCode, String message, Class<?> aClass) {
        this.errorCode = errorCode;
        this.message = message;
        this.aClass = aClass;
    }
}
