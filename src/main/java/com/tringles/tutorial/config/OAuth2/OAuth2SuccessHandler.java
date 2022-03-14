package com.tringles.tutorial.config.OAuth2;

import com.tringles.tutorial.config.JWT.JwtUtil;
import com.tringles.tutorial.domain.user.User;
import com.tringles.tutorial.service.RedisService;
import com.tringles.tutorial.service.UserService;
import lombok.var;
import net.minidev.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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

    @Autowired
    private RedisService redisService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        Object principal = authentication.getPrincipal();
        if (principal instanceof OAuth2User) {
            if (isGoogle(principal)) {
                com.tringles.tutorial.domain.oAuth2.OAuth2User oauth = com.tringles.tutorial.domain.oAuth2.OAuth2User
                        .Provider.google.convert((OAuth2User) principal);
                writeTokenResponse(request, response, oauth);
            } else {
                com.tringles.tutorial.domain.oAuth2.OAuth2User oauth = com.tringles.tutorial.domain.oAuth2.OAuth2User
                        .Provider.kakao.convert((OAuth2User) principal);
                writeTokenResponse(request, response, oauth);
            }
        }
    }

    private void writeTokenResponse(HttpServletRequest request,
                                    HttpServletResponse response,
                                    com.tringles.tutorial.domain.oAuth2.OAuth2User oAuth2User)
            throws IOException, ServletException {
        User user = userService.load(oAuth2User);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities())
        );

        String authToken = JwtUtil.makeAuthToken(user);
        String refreshToken = JwtUtil.makeRefreshToken(user);
        redisService.setValue(refreshToken, user.getEmail());
        _writeTokenResponse(response, authToken, refreshToken);
    }

    private void _writeTokenResponse(HttpServletResponse response,
                                     String authToken,
                                     String refreshToken) throws IOException {
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + authToken);
        response.setHeader("refresh_token", "Bearer " + refreshToken);
        response.setContentType("application/json;charset=UTF-8");

        var writer = response.getWriter();
        JSONObject json = new JSONObject();

        json.put("access_token", authToken);
        json.put("refresh_token", refreshToken);

        writer.write(json.toString());
    }

    private boolean isGoogle(Object principal) {
        return ((OAuth2User) principal).getAttribute("sub") != null;
    }
}
