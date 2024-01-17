package org.fyc.authserver.service;

import jakarta.annotation.Resource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 自定义认证提供商
 */
@Service
public class CustomAuthenticationProvider implements AuthenticationProvider {

    /**
     * 自定义用户信息服务
     */
    @Resource
    private CustomUserDetailsService customUserDetailsService;

    /**
     * 自定义密码编码器
     */
    @Resource
    private PasswordEncoder passwordEncoder;

    /**
     * 认证
     *
     * @param authentication authentication
     * @return authentication
     * @throws AuthenticationException 认证失败
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var username = authentication.getName();
        var password = authentication.getCredentials().toString();
        var user = customUserDetailsService.loadUserByUsername(username);
        return checkPassword(user, password);
    }

    /**
     * 根据用户和输入的密码检查密码是否正确
     *
     * @param user        用户
     * @param rawPassword 输入的密码
     * @return authentication
     */
    private Authentication checkPassword(UserDetails user, String rawPassword) {
        if (passwordEncoder.matches(rawPassword, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(
                    user.getUsername(),
                    user.getPassword(),
                    user.getAuthorities());
        } else {
            throw new BadCredentialsException("Bad Credentials");
        }
    }

    /**
     * 支持
     *
     * @param authentication authentication
     * @return boolean
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
