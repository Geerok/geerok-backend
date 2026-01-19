package io.geerok.core.exception.utils;

public interface ExceptionInterface {
    String getErrorCode();
    String getMessage();
    Class<?> getAClass();
}
