package io.geerok.core.exception;

import lombok.Getter;

@Getter
public abstract class AbstractException extends RuntimeException {
    private final String errorCode;
    private final String message;
    private final String errorLog;

    public AbstractException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
        this.message = message;
        this.errorLog = null;
    }

    public AbstractException(String errorCode, String message, String errorLog) {
        super(message);
        this.errorCode = errorCode;
        this.message = message;
        this.errorLog = errorLog;
    }
}
