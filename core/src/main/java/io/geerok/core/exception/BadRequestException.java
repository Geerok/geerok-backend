package io.geerok.core.exception;

public class BadRequestException extends AbstractException {
    public BadRequestException(String errorCode, String message) {
        super(errorCode, message);
    }

    public BadRequestException(String errorCode, String message, String errorLog) {
        super(errorCode, message, errorLog);
    }
}
