package com.tringles.tutorial.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class UserController {

    @GetMapping("/")
    public String hello() {
        return "Home page";
    }

    @GetMapping("/auth")
    public Object checkUserInfo(@AuthenticationPrincipal Object user){
        return user;
    }
}
