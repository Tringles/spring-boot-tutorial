package com.tringles.tutorial.service;

import com.tringles.tutorial.domain.oAuth2.OAuth2User;
import com.tringles.tutorial.domain.user.User;
import com.tringles.tutorial.domain.user.UserAuthority;
import com.tringles.tutorial.repository.OAuth2UserRepository;
import com.tringles.tutorial.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.HashSet;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private OAuth2UserRepository oAuth2UserRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username).orElseThrow(() -> new UsernameNotFoundException(username));
    }

    public Optional<User> findUser(String email) {
        return userRepository.findByEmail(email);
    }

    public User save(User user) {
        return userRepository.save(user);
    }

    public void addAuthority(Long userId, String authority) {
        userRepository.findById(userId).ifPresent(user -> {
            UserAuthority newRole = new UserAuthority(user.getUserId(), authority);
            if (user.getAuthorities() == null) {
                HashSet<UserAuthority> authorities = new HashSet<>();
                authorities.add(newRole);
                user.setAuthorities(authorities);
                save(user);
            } else if (!user.getAuthorities().contains(newRole)) {
                HashSet<UserAuthority> authorities = new HashSet<>();
                authorities.addAll(user.getAuthorities());
                authorities.add(newRole);
                user.setAuthorities(authorities);
                save(user);
            }
        });
    }

    public void removeAuthority(Long userId, String authority) {
        userRepository.findById(userId).ifPresent(user -> {
            if (user.getAuthorities() == null) return;
            UserAuthority targetRole = new UserAuthority(user.getUserId(), authority);
            if (user.getAuthorities().contains(targetRole)) {
                user.setAuthorities(
                        user.getAuthorities().stream().filter(auth -> !auth.equals(targetRole))
                                .collect(Collectors.toSet())
                );
                save(user);
            }
        });
    }

    public User load(OAuth2User oAuth2User) {
        OAuth2User dbUser = oAuth2UserRepository.findById(oAuth2User.getOauth2UserId())
                .orElseGet(() -> {
                    User user = new User();
                    user.setEmail(oAuth2User.getEmail());
                    user.setName(oAuth2User.getName());
                    user.setEnabled(true);
                    user = userRepository.save(user);
                    addAuthority(user.getUserId(), "ROLE_USER");

                    oAuth2User.setUserId(user.getUserId());
                    return oAuth2UserRepository.save(oAuth2User);
                });
        return userRepository.findById(dbUser.getUserId()).get();
    }
}
