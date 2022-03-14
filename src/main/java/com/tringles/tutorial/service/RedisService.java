package com.tringles.tutorial.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate redisTemplate;

    public void setValue(String token, String email) {
        ValueOperations<String, String> value = redisTemplate.opsForValue();
        value.set(token, email, Duration.ofHours(168));
    }

    public String getValue(String token) {
        ValueOperations<String, String> value = redisTemplate.opsForValue();
        return value.get(token);
    }

    public void delValue(String token) {
        redisTemplate.delete(token.substring("bearer ".length()));
    }

    public boolean isRefreshTokenInRedis(String refreshToken) {
        return this.getValue(refreshToken) != null;
    }
}
