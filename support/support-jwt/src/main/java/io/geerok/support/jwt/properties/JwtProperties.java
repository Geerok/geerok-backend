package io.geerok.support.jwt.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "support.jwt")
public class JwtProperties {
    private JsonWebToken accessToken;
    private JsonWebToken refreshToken;

    @Data
    public static class JsonWebToken {
        public String tokenKey;
        public String secretKey;
        public Long expiresIn;
    }
}
