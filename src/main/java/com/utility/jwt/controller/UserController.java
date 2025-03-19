package com.utility.jwt.controller;

import com.utility.jwt.entity.User;
import com.utility.jwt.service.UserService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    private UserService userService;

    @PostConstruct
    public void initRolesAndUsers(){
        userService.initRolesAndUser();
    }
    @PostMapping({"/register-newuser"})
    public User registerNewUser(@RequestBody User user){
        return userService.registerNewUser(user);
    }

    @GetMapping({"/for-admin"})

    public String forAdmin(){
        return  "This URL is only accessible to admin";
    }

    @GetMapping({"/for-user"})

    public String forUser(){
        return  "This URL is only accessible to user";
    }
}
