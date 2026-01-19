package io.geerok.core.exception;

public class NotFoundException extends AbstractException {
    public NotFoundException(String errorCode, String message) {
        super(errorCode, message);
    }

    public NotFoundException(String errorCode, String message, String errorLog) {
        super(errorCode, message, errorLog);
    }
}
