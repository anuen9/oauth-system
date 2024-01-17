package org.fyc.authserver.config;

import jakarta.annotation.Resource;
import org.fyc.authserver.service.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * spring security 配置
 */
@Configuration
@EnableWebSecurity
public class DefaultSecurityConfig {

    /**
     * 自定义认证提供商
     */
    @Resource
    private CustomAuthenticationProvider customAuthenticationProvider;

    /**
     * 配置过滤器链
     *
     * @param http http
     * @return 过滤器链
     * @throws Exception exception
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    auth.anyRequest().authenticated();
                })
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    /**
     * 绑定认证提供商
     *
     * @param authenticationManagerBuilder authentication manager builder
     */
    @Autowired
    public void bindAuthenticationProvider(AuthenticationManagerBuilder authenticationManagerBuilder) {
        authenticationManagerBuilder
                .authenticationProvider(customAuthenticationProvider);
    }

}
