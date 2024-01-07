package org.fyc.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;

/**
 * 认证服务器配置
 */
@RequiredArgsConstructor
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    /**
     * 自定义密码编码器
     */
    private final PasswordEncoder passwordEncoder;

    /**
     * 最高等级的过滤器链 配置为默认
     *
     * @param http http
     * @return 过滤器链
     * @throws Exception exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    /**
     * 客户端需要注册到授权服务器并持久化，该处的持久化为jdbc实现
     * 基于数据库持久化客户端信息，默认的实现为基于内存的Client信息管理，不建议生产使用
     *
     * @param template jdbc bean
     * @return 基于数据库的客户端仓库
     */
    @Bean
    RegisteredClientRepository registeredClientRepository(JdbcTemplate template) {
        return new JdbcRegisteredClientRepository(template);
    }

    /**
     * 实现ApplicationRunner接口中的run方法实现配置客户端
     *
     * @param repository 上述配置中的基于数据库的客户端信息仓库bean
     * @return 运行器
     */
    @Bean
    ApplicationRunner clientsRunner(RegisteredClientRepository repository) {
        return args -> {
            var clientId = "dni";
            if (repository.findByClientId(clientId) == null) { // 如果数据库中不存在客户端id为"dni"的客户端信息
                repository.save( // 保存客户端信息，是实现配置客户端的终结步骤
                        RegisteredClient
                                .withId(UUID.randomUUID().toString())
                                .clientId(clientId) // 客户端id
                                .clientSecret(passwordEncoder.encode(clientId)) // 客户端密钥
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(
                                        AuthorizationGrantType.CLIENT_CREDENTIALS,
                                        AuthorizationGrantType.AUTHORIZATION_CODE,
                                        AuthorizationGrantType.REFRESH_TOKEN)))
                                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/spring") // 重定向uri
                                .scopes(scope -> scope.addAll(Set.of("user.read", "user.write", OidcScopes.OPENID)))
                                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                                .build()
                );
            }
        };
    }

    /**
     * jwk（生成jwt的密钥）配置
     *
     * @return jwk source
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    /**
     * 生成RSA密钥
     *
     * @return rsa key
     */
    private static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    /**
     * 生成rsa的密钥
     *
     * @return key pair
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return keyPair;
    }

}
