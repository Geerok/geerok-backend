package io.geerok.core.exception;

public class ServiceUnavailableException extends AbstractException {
    public ServiceUnavailableException(String errorCode, String message) {
        super(errorCode, message);
    }

    public ServiceUnavailableException(String errorCode, String message, String errorLog) {
        super(errorCode, message, errorLog);
    }
}
