package com.tringles.tutorial.config;

import com.tringles.tutorial.config.JWT.JwtCheckFilter;
import com.tringles.tutorial.config.OAuth2.OAuth2SuccessHandler;
import com.tringles.tutorial.service.OAuth2UserService;
import com.tringles.tutorial.service.RedisService;
import com.tringles.tutorial.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@EnableWebSecurity()
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private OAuth2UserService oAuth2UserService;

    @Autowired
    private OAuth2SuccessHandler successHandler;

    @Autowired
    private UserService userService;

    @Autowired
    private RedisService redisService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JwtCheckFilter checkFilter = new JwtCheckFilter(authenticationManager(), userService, redisService);

        http
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeRequests()
                .antMatchers("/").authenticated()
                .and()
                .oauth2Login().successHandler(successHandler)
                .userInfoEndpoint().userService(oAuth2UserService)
        ;
        http
                .addFilterBefore(new JwtCheckFilter(authenticationManager(), userService, redisService),
                        UsernamePasswordAuthenticationFilter.class);
    }
}
