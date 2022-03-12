package com.tringles.tutorial.config.OAuth2;

import com.tringles.tutorial.config.JWT.JwtUtil;
import com.tringles.tutorial.domain.User;
import com.tringles.tutorial.service.UserService;
import lombok.var;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private UserService userService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        Object principal = authentication.getPrincipal();
        if (principal instanceof OAuth2User) {
            if (isGoogle(principal)) {
                com.tringles.tutorial.domain.OAuth2User oauth = com.tringles.tutorial.domain.OAuth2User
                        .Provider.google.convert((OAuth2User) principal);
                User user = userService.load(oauth);
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities())
                );

                String authToken = JwtUtil.makeAuthToken(user);
                writeTokenResponse(response, authToken);
            } else {
                com.tringles.tutorial.domain.OAuth2User oauth = com.tringles.tutorial.domain.OAuth2User
                        .Provider.kakao.convert((OAuth2User) principal);
                User user = userService.load(oauth);
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities())
                );

                String authToken = JwtUtil.makeAuthToken(user);
                writeTokenResponse(response, authToken);
            }
        }
    }

    private void writeTokenResponse(HttpServletResponse response, String authToken) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + authToken);
        response.setContentType("application/json;charset=UTF-8");

        var writer = response.getWriter();
        writer.println(authToken);
        writer.flush();
    }

    private boolean isGoogle(Object principal) {
        return ((OAuth2User) principal).getAttribute("sub") != null;
    }
}
