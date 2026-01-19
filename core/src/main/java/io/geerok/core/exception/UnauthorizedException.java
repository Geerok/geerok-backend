package io.geerok.core.exception;

public class UnauthorizedException extends AbstractException {
    public UnauthorizedException(String errorCode, String message) {
        super(errorCode, message);
    }

    public UnauthorizedException(String errorCode, String message, String errorLog) {
        super(errorCode, message, errorLog);
    }
}
