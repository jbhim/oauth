package com.example.oauth.provider;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * 短信登录验证提供程序
 * @author jintao
 */
@Slf4j
public class PhoneCodeAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info(authentication.getName());
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        log.info(authentication.getName());
        return PhoneCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
