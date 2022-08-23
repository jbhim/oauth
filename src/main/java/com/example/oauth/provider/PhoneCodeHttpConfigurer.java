package com.example.oauth.provider;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * @author jintao
 */
public class PhoneCodeHttpConfigurer extends AbstractHttpConfigurer<PhoneCodeHttpConfigurer, HttpSecurity> {

    public static PhoneCodeHttpConfigurer phoneCodeLogin(UserDetailsService userDetailsService) {
        return new PhoneCodeHttpConfigurer(userDetailsService);
    }

    public PhoneCodeHttpConfigurer(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    private UserDetailsService userDetailsService;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        PhoneCodeAuthenticationFilter filter = new PhoneCodeAuthenticationFilter(authenticationManager);
        http
                .authenticationProvider(new PhoneCodeAuthenticationProvider(userDetailsService))
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }

    public UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}