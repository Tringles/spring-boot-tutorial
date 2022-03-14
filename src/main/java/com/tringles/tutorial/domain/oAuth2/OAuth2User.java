package com.tringles.tutorial.domain.oAuth2;

import com.tringles.tutorial.domain.base.BaseTimeEntity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import java.util.Map;

import static java.lang.String.format;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
@Table(name = "oauth2_users")
public class OAuth2User extends BaseTimeEntity {

    @Id
    private String oauth2UserId;

    private Long userId;
    private String name;
    private String email;
    private Provider provider;

    public static enum Provider {
        google {
            public OAuth2User convert(org.springframework.security.oauth2.core.user.OAuth2User user) {
                return OAuth2User.builder()
                        .oauth2UserId(format("%s_%s", name(), user.getAttribute("sub")))
                        .provider(google)
                        .email(user.getAttribute("email"))
                        .name(user.getAttribute("name"))
                        .build()
                        ;
            }
        },
        kakao {
            public OAuth2User convert(org.springframework.security.oauth2.core.user.OAuth2User user) {
                Map<String, Object> kakaoAccount = user.getAttribute("kakao_account");
                Map<String, Object> kakaoProfile = (Map<String, Object>) kakaoAccount.get("profile");

                return OAuth2User.builder()
                        .provider(kakao)
                        .email((String) kakaoAccount.get("email"))
                        .name((String) kakaoProfile.get("nickname"))
                        .oauth2UserId(format("%s_%s", name(), user.getAttribute("id")))
                        .build()
                        ;
            }
        };

        public abstract OAuth2User convert(org.springframework.security.oauth2.core.user.OAuth2User user);
    }
}
