package org.fyc.authserver;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan("org.fyc.authserver.repository")
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }

//    @Bean
//    PasswordEncoder passwordEncoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }
}

//@Configuration
//class AuthorizationConfiguration {
//    @Bean
//    JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService(
//            JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
//        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, repository);
//    }
//
//    @Bean
//    JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService(
//            JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
//        return new JdbcOAuth2AuthorizationService(jdbcOperations, repository);
//    }
//}
//
//@Configuration
//class UserConfiguration {
//    @Bean
//    JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
//        return new JdbcUserDetailsManager(dataSource);
//    }
//
//    @Bean
//    ApplicationRunner usersRunner(UserDetailsManager userDetailsManager) {
//        return args -> {
//            var userBuilder = User.builder().roles("USER");
//            var users = Map.of("john", "{bcrypt}$2a$10$y9RT2Kchzl1QnpxwWQdVT..m9dv5nUVWiw16kpccWo4CRa6NpZiOu",
//                    "jack", "{bcrypt}$2a$10$nn6P./mCq5HWuMXj5l/lL.3Vtu9Na1zwUAzzr273UCooKeV6FH0jm");
//            users.forEach((username, password) -> {
//                if (!userDetailsManager.userExists(username)) {
//                    var user = userBuilder
//                            .username(username)
//                            .password(password)
//                            .build();
//                    userDetailsManager.createUser(user);
//                }
//            });
//        };
//    }
//}
//
//
//@Configuration
//class ClientsConfiguration {
//    @Bean
//    RegisteredClientRepository registeredClientRepository(JdbcTemplate template) {
//        return new JdbcRegisteredClientRepository(template);
//    }
//
//    @Bean
//    ApplicationRunner clientsRunner(RegisteredClientRepository repository) {
//        return args -> {
//            var clientId = "dni";
//            if (repository.findByClientId(clientId) == null) {
//                repository.save(
//                        RegisteredClient
//                                .withId(UUID.randomUUID().toString())
//                                .clientId(clientId)
//                                .clientSecret("{bcrypt}$2a$10$XRH.2kuTv/yQvkA02yHQ.uNjc7/ZQ87oEZQ6DQaALgvmytV//X1mS")
//                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                                .authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(
//                                        AuthorizationGrantType.CLIENT_CREDENTIALS,
//                                        AuthorizationGrantType.AUTHORIZATION_CODE,
//                                        AuthorizationGrantType.REFRESH_TOKEN)))
//                                .redirectUri("http://127.0.0.1:8082/login/oauth2/code/spring")
//                                .scopes(scope -> scope.addAll(Set.of("user.read", "user.write", OidcScopes.OPENID)))
//                                .build()
//                );
//            }
//        };
//    }
//}
