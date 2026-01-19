package io.geerok.core.exception;

public class InternalServerErrorException extends AbstractException {
    public InternalServerErrorException(String errorCode, String message) {
        super(errorCode, message);
    }

    public InternalServerErrorException(String errorCode, String message, String errorLog) {
        super(errorCode, message, errorLog);
    }
}
