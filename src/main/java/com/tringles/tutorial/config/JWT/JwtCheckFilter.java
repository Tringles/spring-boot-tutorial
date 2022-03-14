package com.tringles.tutorial.config.JWT;

import com.tringles.tutorial.domain.user.User;
import com.tringles.tutorial.dto.VerifyResult;
import com.tringles.tutorial.service.RedisService;
import com.tringles.tutorial.service.UserService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtCheckFilter extends BasicAuthenticationFilter {

    private UserService userService;
    private RedisService redisService;

    public JwtCheckFilter(AuthenticationManager authenticationManager, UserService userService, RedisService redisService) {
        super(authenticationManager);
        this.userService = userService;
        this.redisService = redisService;
    }

    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String authToken = JwtUtil.resolveAuthToken(request);
        String refreshToken = JwtUtil.resolveRefreshToken(request);

        if (authToken == null) {
            chain.doFilter(request, response);
            return;
        }

        VerifyResult verifyAuthToken = JwtUtil.verify(authToken);
        VerifyResult verifyRefreshToken = JwtUtil.verify(refreshToken);

        if (verifyAuthToken.isSuccess()) {
            this.setAuthentication(verifyAuthToken);
            chain.doFilter(request, response);
        } else if (verifyRefreshToken.isSuccess() && redisService.isRefreshTokenInRedis(refreshToken)) {
            User user = (User) userService.loadUserByUsername(redisService.getValue(refreshToken));
            String newAuthToken = JwtUtil.makeAuthToken(user);

            response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + newAuthToken);
            this.setAuthentication(verifyRefreshToken);
        }
        chain.doFilter(request, response);
    }

    private void setAuthentication(VerifyResult verifyResult) {
        UserDetails userDetails = userService.loadUserByUsername(verifyResult.getUsername());
        UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(
                userDetails.getUsername(), null, userDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(userToken);
    }
}
