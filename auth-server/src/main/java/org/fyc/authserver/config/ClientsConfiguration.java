//package org.fyc.authserver.config;
//
//import org.springframework.boot.ApplicationRunner;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.jdbc.core.JdbcTemplate;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//
//import java.util.Set;
//import java.util.UUID;
//
///**
// * 客户端配置类
// */
//@Configuration
//public class ClientsConfiguration {
//    /**
//     * 客户端需要注册到授权服务器并持久化，该处的持久化为jdbc实现
//     * 基于数据库持久化客户端信息，默认的实现为基于内存的Client信息管理，不建议生产使用
//     *
//     * @param template jdbc bean
//     * @return 基于数据库的客户端仓库
//     */
//    @Bean
//    RegisteredClientRepository registeredClientRepository(JdbcTemplate template) {
//        return new JdbcRegisteredClientRepository(template);
//    }
//
//    /**
//     * 实现ApplicationRunner接口中的run方法实现配置客户端
//     *
//     * @param repository 上述配置中的基于数据库的客户端信息仓库bean
//     * @return 运行器
//     */
//    @Bean
//    ApplicationRunner clientsRunner(RegisteredClientRepository repository) {
//        return args -> {
//            var clientId = "dni";
//            if (repository.findByClientId(clientId) == null) { // 如果数据库中不存在客户端id为"dni"的客户端信息
//                repository.save( // 保存客户端信息，是实现配置客户端的终结步骤
//                        RegisteredClient
//                                .withId(UUID.randomUUID().toString())
//                                .clientId(clientId) // 客户端id
//                                .clientSecret("{bcrypt}$2a$10$XRH.2kuTv/yQvkA02yHQ.uNjc7/ZQ87oEZQ6DQaALgvmytV//X1mS") // 客户端密钥
//                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(
//                                        AuthorizationGrantType.CLIENT_CREDENTIALS,
//                                        AuthorizationGrantType.AUTHORIZATION_CODE,
//                                        AuthorizationGrantType.REFRESH_TOKEN)))
//                                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/spring") // 重定向uri
//                                .scopes(scope -> scope.addAll(Set.of("user.read", "user.write", OidcScopes.OPENID)))
//                                .build()
//                );
//            }
//        };
//    }
//}
