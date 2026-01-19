package io.geerok.core.exception;

public class ForbiddenException extends AbstractException {
    public ForbiddenException(String errorCode, String message) {
        super(errorCode, message);
    }

    public ForbiddenException(String errorCode, String message, String errorLog) {
        super(errorCode, message, errorLog);
    }
}
