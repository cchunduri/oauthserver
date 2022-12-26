package com.chaiapps.oauthserver.controllers

import com.chaiapps.oauthserver.dto.LoginDTO
import com.chaiapps.oauthserver.security.TokenProvider
import com.chaiapps.oauthserver.utils.SecurityConstants.Companion.AUTHORIZATION_HEADER
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController


@RestController
@RequestMapping("/users")
class UserController(
    val authenticationManagerBuilder: AuthenticationManagerBuilder,
    val tokenProvider: TokenProvider
) {

    @PostMapping("/register")
    fun registerUser(): String {
        return "Fun"
    }

    @PostMapping("/login")
    fun loginUser(
        @RequestBody loginDTO: LoginDTO
    ): ResponseEntity<JWTToken> {
        val authenticationToken = UsernamePasswordAuthenticationToken(
            loginDTO.username,
            loginDTO.password
        )

        val authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken)
        SecurityContextHolder.getContext().authentication = authentication
        val jwt: String = tokenProvider.createToken(authentication, true)
        val httpHeaders = HttpHeaders()
        httpHeaders.add(AUTHORIZATION_HEADER, "Bearer $jwt")
        return ResponseEntity<JWTToken>(JWTToken(jwt), httpHeaders, HttpStatus.OK)
    }

    class JWTToken(@get:JsonProperty("id_token") var idToken: String)
}