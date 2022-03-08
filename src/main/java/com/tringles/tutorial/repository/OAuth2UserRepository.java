package com.tringles.tutorial.repository;

import com.tringles.tutorial.domain.OAuth2User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2UserRepository extends JpaRepository<OAuth2User, String> {
}
