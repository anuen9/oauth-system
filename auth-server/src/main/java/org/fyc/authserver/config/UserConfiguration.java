//package org.fyc.authserver.config;
//
//import org.springframework.boot.ApplicationRunner;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.provisioning.JdbcUserDetailsManager;
//import org.springframework.security.provisioning.UserDetailsManager;
//
//import javax.sql.DataSource;
//import java.util.Map;
//
///**
// * 用户配置类
// */
//@Configuration
//public class UserConfiguration {
//    /**
//     * 配置基于数据库的用户信息管理器
//     *
//     * @param dataSource 数据源
//     * @return 基于数据库的用户信息管理器
//     */
//    @Bean
//    JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
//        return new JdbcUserDetailsManager(dataSource);
//    }
//
//    /**
//     * 配置用户进数据库
//     *
//     * @param userDetailsManager 上述申明的用户信息管理器
//     * @return 运行器
//     */
//    @Bean
//    ApplicationRunner usersRunner(UserDetailsManager userDetailsManager) {
//        return args -> {
//            var userBuilder = User.builder().roles("USER"); // 用户角色默认为USER
//            var users = Map.of("john", "{bcrypt}$2a$10$y9RT2Kchzl1QnpxwWQdVT..m9dv5nUVWiw16kpccWo4CRa6NpZiOu",
//                    "jack", "{bcrypt}$2a$10$nn6P./mCq5HWuMXj5l/lL.3Vtu9Na1zwUAzzr273UCooKeV6FH0jm");
//            users.forEach((username, password) -> {
//                if (!userDetailsManager.userExists(username)) { // 如果用户不存在的话保存用户信息到数据库中
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
