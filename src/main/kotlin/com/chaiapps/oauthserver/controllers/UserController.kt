package com.chaiapps.oauthserver.controllers

import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/users")
class UserController {
    @PostMapping("/register")
    fun registerUser(): String {
        return "Fun"
    }
}