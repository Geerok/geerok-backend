package io.geerok.support.jwt.fixture;

import io.geerok.support.jwt.properties.JwtProperties;

public class JwtPropertiesTestFixture {
    public static final String TEST_ACCESS_SECRET_KEY = "R2Vlcm9rQWNjZXNzVG9rZW5TZWN1cmVLZXlGb3JKV1RBdXRoZW50aWNhdGlvbldpdGhIUzUxMkFsZ29yaXRobUFuZFN0cm9uZ1NlY3VyaXR5MTIz";
    public static final String TEST_REFRESH_SECRET_KEY = "R2Vlcm9rUmVmcmVzaFRva2VuU2VjdXJlS2V5Rm9yTG9uZ1Rlcm1BdXRoZW50aWNhdGlvblNlc3Npb25NYW5hZ2VtZW50V2l0aEhTNTEyNDU2";
    public static final Long TEST_EXPIRES_IN = 1800L;

    public static JwtProperties create() {
        JwtProperties properties = new JwtProperties();

        JwtProperties.JsonWebToken accessToken = new JwtProperties.JsonWebToken();
        accessToken.setTokenKey("access-token");
        accessToken.setSecretKey(TEST_ACCESS_SECRET_KEY);
        accessToken.setExpiresIn(TEST_EXPIRES_IN);

        JwtProperties.JsonWebToken refreshToken = new JwtProperties.JsonWebToken();
        refreshToken.setTokenKey("refresh-token");
        refreshToken.setSecretKey(TEST_REFRESH_SECRET_KEY);
        refreshToken.setExpiresIn(TEST_EXPIRES_IN);

        properties.setAccessToken(accessToken);
        properties.setRefreshToken(refreshToken);

        return properties;
    }
}
