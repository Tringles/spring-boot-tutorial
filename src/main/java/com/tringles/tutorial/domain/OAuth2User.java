package com.tringles.tutorial.domain;

import com.tringles.tutorial.domain.base.BaseTimeEntity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

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
        naver {
            public OAuth2User convert(org.springframework.security.oauth2.core.user.OAuth2User user) {
                return null;
            }
        };

        public abstract OAuth2User convert(org.springframework.security.oauth2.core.user.OAuth2User user);
    }
}
