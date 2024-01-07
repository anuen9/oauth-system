//package org.fyc.authserver.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.jdbc.core.JdbcOperations;
//import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
//import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//
///**
// * 认证配置类
// */
//@Configuration
//public class AuthorizationConfiguration {
//    /**
//     * 管理oauth2已经确认授权的信息服务
//     *
//     * @param jdbcOperations the jdbc operations
//     * @param repository     the registered client repository
//     * @return jdbcOauth2AuthorizationConsentService
//     */
//    @Bean
//    JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService(
//            JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
//        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, repository);
//    }
//
//    /**
//     * 管理oauth2授权信息服务
//     *
//     * @param jdbcOperations the jdbc operations
//     * @param repository     the registered client repository
//     * @return jdbcOauth2AuthorizationService
//     */
//    @Bean
//    JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService(
//            JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
//        return new JdbcOAuth2AuthorizationService(jdbcOperations, repository);
//    }
//}
