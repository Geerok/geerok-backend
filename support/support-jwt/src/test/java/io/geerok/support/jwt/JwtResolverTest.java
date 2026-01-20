package io.geerok.support.jwt;

import io.geerok.core.exception.UnauthorizedException;
import io.geerok.support.jwt.dto.AccessTokenPayload;
import io.geerok.support.jwt.dto.RefreshTokenPayload;
import io.geerok.support.jwt.fixture.JwtPropertiesTestFixture;
import io.geerok.support.jwt.fixture.AccessTokenPayloadTestFixture;
import io.geerok.support.jwt.properties.JwtProperties;
import io.geerok.support.jwt.tokens.AccessToken;
import io.geerok.support.jwt.tokens.RefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("JwtResolver 테스트")
class JwtResolverTest {

    private JwtProvider jwtProvider;
    private JwtResolver jwtResolver;

    @BeforeEach
    void setUp() {
        JwtProperties jwtProperties = JwtPropertiesTestFixture.create();

        jwtProvider = new JwtProvider(jwtProperties);
        jwtProvider.init();

        ObjectMapper objectMapper = new ObjectMapper();
        jwtResolver = new JwtResolver(jwtProperties, objectMapper);
        jwtResolver.init();
    }

    @Nested
    @DisplayName("AccessToken 파싱")
    class GetPayloadFromAccessToken {

        @Test
        @DisplayName("유효한 AccessToken에서 payload를 추출한다")
        void shouldExtractPayloadFromValidAccessToken() {
            // given
            AccessTokenPayload originalPayload = AccessTokenPayloadTestFixture.create();
            AccessToken accessToken = jwtProvider.generateAccessToken(originalPayload);

            // when
            AccessTokenPayload extractedPayload = jwtResolver.getPayloadFromAccessToken(accessToken.token());

            // then
            assertThat(extractedPayload.userId()).isEqualTo(originalPayload.userId());
            assertThat(extractedPayload.nickname()).isEqualTo(originalPayload.nickname());
            assertThat(extractedPayload.authorities()).containsExactlyElementsOf(originalPayload.authorities());
        }

        @Test
        @DisplayName("다중 권한을 가진 AccessToken에서 모든 권한을 추출한다")
        void shouldExtractMultipleAuthoritiesFromAccessToken() {
            // given
            List<String> authorities = List.of("ROLE_USER", "ROLE_ADMIN", "ROLE_MANAGER");
            AccessTokenPayload originalPayload = AccessTokenPayloadTestFixture.create(1L, "testUser", authorities);
            AccessToken accessToken = jwtProvider.generateAccessToken(originalPayload);

            // when
            AccessTokenPayload extractedPayload = jwtResolver.getPayloadFromAccessToken(accessToken.token());

            // then
            assertThat(extractedPayload.authorities()).hasSize(3);
            assertThat(extractedPayload.authorities()).containsExactlyElementsOf(authorities);
        }

        @Test
        @DisplayName("null 토큰이 주어지면 예외를 발생시킨다")
        void shouldThrowExceptionWhenTokenIsNull() {
            // when & then
            assertThatThrownBy(() -> jwtResolver.getPayloadFromAccessToken(null))
                    .isInstanceOf(UnauthorizedException.class);
        }

        @Test
        @DisplayName("잘못된 형식의 토큰이 주어지면 예외를 발생시킨다")
        void shouldThrowExceptionWhenTokenIsInvalid() {
            // given
            String invalidToken = "invalid.token.format";

            // when & then
            assertThatThrownBy(() -> jwtResolver.getPayloadFromAccessToken(invalidToken))
                    .isInstanceOf(UnauthorizedException.class);
        }

        @Test
        @DisplayName("변조된 토큰이 주어지면 예외를 발생시킨다")
        void shouldThrowExceptionWhenTokenIsTampered() {
            // given
            AccessTokenPayload payload = AccessTokenPayloadTestFixture.create();
            AccessToken accessToken = jwtProvider.generateAccessToken(payload);
            String tamperedToken = accessToken.token() + "tampered";

            // when & then
            assertThatThrownBy(() -> jwtResolver.getPayloadFromAccessToken(tamperedToken))
                    .isInstanceOf(UnauthorizedException.class);
        }
    }

    @Nested
    @DisplayName("RefreshToken 파싱")
    class GetPayloadFromRefreshToken {

        @Test
        @DisplayName("유효한 RefreshToken에서 payload를 추출한다")
        void shouldExtractPayloadFromValidRefreshToken() {
            // given
            Long userId = 1L;
            RefreshToken refreshToken = jwtProvider.generateRefreshToken(userId);

            // when
            RefreshTokenPayload extractedPayload = jwtResolver.getPayloadFromRefreshToken(refreshToken.token());

            // then
            assertThat(extractedPayload.userId()).isEqualTo(userId);
        }

        @Test
        @DisplayName("null 토큰이 주어지면 예외를 발생시킨다")
        void shouldThrowExceptionWhenTokenIsNull() {
            // when & then
            assertThatThrownBy(() -> jwtResolver.getPayloadFromRefreshToken(null))
                    .isInstanceOf(UnauthorizedException.class);
        }

        @Test
        @DisplayName("잘못된 형식의 토큰이 주어지면 예외를 발생시킨다")
        void shouldThrowExceptionWhenTokenIsInvalid() {
            // given
            String invalidToken = "invalid.token.format";

            // when & then
            assertThatThrownBy(() -> jwtResolver.getPayloadFromRefreshToken(invalidToken))
                    .isInstanceOf(UnauthorizedException.class);
        }

        @Test
        @DisplayName("AccessToken을 RefreshToken으로 파싱하면 예외를 발생시킨다")
        void shouldThrowExceptionWhenAccessTokenUsedAsRefreshToken() {
            // given
            AccessTokenPayload payload = AccessTokenPayloadTestFixture.create();
            AccessToken accessToken = jwtProvider.generateAccessToken(payload);

            // when & then
            assertThatThrownBy(() -> jwtResolver.getPayloadFromRefreshToken(accessToken.token()))
                    .isInstanceOf(UnauthorizedException.class);
        }

        @Test
        @DisplayName("RefreshToken을 AccessToken으로 파싱하면 예외를 발생시킨다")
        void shouldThrowExceptionWhenRefreshTokenUsedAsAccessToken() {
            // given
            RefreshToken refreshToken = jwtProvider.generateRefreshToken(1L);

            // when & then
            assertThatThrownBy(() -> jwtResolver.getPayloadFromAccessToken(refreshToken.token()))
                    .isInstanceOf(UnauthorizedException.class);
        }
    }
}
