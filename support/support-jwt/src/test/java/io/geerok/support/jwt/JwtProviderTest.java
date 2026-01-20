package io.geerok.support.jwt;

import io.geerok.support.jwt.dto.AccessTokenPayload;
import io.geerok.support.jwt.fixture.JwtPropertiesTestFixture;
import io.geerok.support.jwt.fixture.AccessTokenPayloadTestFixture;
import io.geerok.support.jwt.properties.JwtProperties;
import io.geerok.support.jwt.tokens.AccessToken;
import io.geerok.support.jwt.tokens.RefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JwtProvider 테스트")
class JwtProviderTest {

    private JwtProvider jwtProvider;
    private JwtProperties jwtProperties;

    @BeforeEach
    void setUp() {
        jwtProperties = JwtPropertiesTestFixture.create();
        jwtProvider = new JwtProvider(jwtProperties);
        jwtProvider.init();
    }

    @Nested
    @DisplayName("AccessToken 생성")
    class GenerateAccessToken {

        @Test
        @DisplayName("유효한 payload로 AccessToken을 생성한다")
        void shouldGenerateAccessTokenWithValidPayload() {
            // given
            AccessTokenPayload payload = AccessTokenPayloadTestFixture.create();

            // when
            AccessToken accessToken = jwtProvider.generateAccessToken(payload);

            // then
            assertThat(accessToken).isNotNull();
            assertThat(accessToken.token()).isNotBlank();
            assertThat(accessToken.expiresAt()).isAfter(LocalDateTime.now());
        }

        @Test
        @DisplayName("다양한 권한을 가진 payload로 AccessToken을 생성한다")
        void shouldGenerateAccessTokenWithMultipleAuthorities() {
            // given
            AccessTokenPayload payload = AccessTokenPayloadTestFixture.create(
                    1L,
                    "adminUser",
                    List.of("ROLE_USER", "ROLE_ADMIN")
            );

            // when
            AccessToken accessToken = jwtProvider.generateAccessToken(payload);

            // then
            assertThat(accessToken).isNotNull();
            assertThat(accessToken.token()).isNotBlank();
        }

        @Test
        @DisplayName("생성된 AccessToken의 만료 시간이 설정된 expiresIn과 일치한다")
        void shouldHaveCorrectExpirationTime() {
            // given
            AccessTokenPayload payload = AccessTokenPayloadTestFixture.create();
            LocalDateTime beforeGeneration = LocalDateTime.now();

            // when
            AccessToken accessToken = jwtProvider.generateAccessToken(payload);

            // then
            LocalDateTime expectedMinExpiry = beforeGeneration.plusSeconds(jwtProperties.getAccessToken().getExpiresIn());
            assertThat(accessToken.expiresAt()).isAfterOrEqualTo(expectedMinExpiry.minusSeconds(1));
        }
    }

    @Nested
    @DisplayName("RefreshToken 생성")
    class GenerateRefreshToken {

        @Test
        @DisplayName("유효한 userId로 RefreshToken을 생성한다")
        void shouldGenerateRefreshTokenWithValidUserId() {
            // given
            Long userId = 1L;

            // when
            RefreshToken refreshToken = jwtProvider.generateRefreshToken(userId);

            // then
            assertThat(refreshToken).isNotNull();
            assertThat(refreshToken.token()).isNotBlank();
            assertThat(refreshToken.expiresAt()).isAfter(LocalDateTime.now());
        }

        @Test
        @DisplayName("동일한 userId로 생성된 RefreshToken은 매번 다른 값을 가진다")
        void shouldGenerateDifferentTokensForSameUserId() {
            // given
            Long userId = 1L;

            // when
            RefreshToken token1 = jwtProvider.generateRefreshToken(userId);
            RefreshToken token2 = jwtProvider.generateRefreshToken(userId);

            // then
            assertThat(token1.token()).isNotEqualTo(token2.token());
        }

        @Test
        @DisplayName("생성된 RefreshToken의 만료 시간이 설정된 expiresIn과 일치한다")
        void shouldHaveCorrectExpirationTime() {
            // given
            Long userId = 1L;
            LocalDateTime beforeGeneration = LocalDateTime.now();

            // when
            RefreshToken refreshToken = jwtProvider.generateRefreshToken(userId);

            // then
            LocalDateTime expectedMinExpiry = beforeGeneration.plusSeconds(jwtProperties.getRefreshToken().getExpiresIn());
            assertThat(refreshToken.expiresAt()).isAfterOrEqualTo(expectedMinExpiry.minusSeconds(1));
        }
    }
}
