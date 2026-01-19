package io.geerok.core.exception.utils;

import io.geerok.core.exception.AbstractException;

import java.lang.reflect.Constructor;

public class ExceptionCreator {
    @SuppressWarnings("unchecked")
    private static <T> T createInstance(Class<? extends T> clazz, Object... args) {
        Constructor<? extends T>[] constructorArray = (Constructor<? extends T>[]) clazz.getDeclaredConstructors();
        for (Constructor<? extends T> constructor : constructorArray) {
            try {
                return constructor.newInstance(args);
            } catch (Exception ignored) {

            }
        }
        throw new RuntimeException("Failed to create HttpException instance");
    }

    public static AbstractException create(ExceptionInterface e) {
        return (AbstractException) createInstance(e.getAClass(),e.getErrorCode(), e.getMessage());
    }

    public static AbstractException create(ExceptionInterface e, String errorLog) {
        return (AbstractException) createInstance(e.getAClass(), e.getErrorCode(), e.getMessage(), errorLog);
    }
}
