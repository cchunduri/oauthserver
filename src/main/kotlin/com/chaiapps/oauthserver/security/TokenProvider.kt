package com.chaiapps.oauthserver.security

import com.chaiapps.oauthserver.utils.SecurityConstants.Companion.AUTHORITIES_KEY
import com.chaiapps.oauthserver.utils.SecurityConstants.Companion.INVALID_JWT_TOKEN
import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import java.nio.charset.StandardCharsets
import java.security.Key
import java.util.*
import java.util.stream.Collectors

@Component
class TokenProvider(
    private var key: Key? = null,
    private var jwtParser: JwtParser? = null
) {

    init {
        val secret = "AuthenticationKeyOAuthSecret%^525^"
        key = Keys.hmacShaKeyFor(secret.toByteArray(StandardCharsets.UTF_8))
        jwtParser = Jwts.parserBuilder().setSigningKey(key).build()
    }

    private val log = LoggerFactory.getLogger(TokenProvider::class.java)

    private val tokenValidityInMilliseconds: Long = 24*60*60*1000
    private val tokenValidityInMillisecondsForRememberMe: Long = 60*60*1000

    fun createToken(authentication: Authentication, rememberMe: Boolean): String {
        val authorities = authentication.authorities.stream().map { obj: GrantedAuthority -> obj.authority }
            .collect(Collectors.joining(","))
        val now = Date().time
        val validity: Date = if (rememberMe) {
            Date(now + this.tokenValidityInMillisecondsForRememberMe)
        } else {
            Date(now + this.tokenValidityInMilliseconds)
        }

        return Jwts
            .builder()
            .setSubject(authentication.name)
            .claim(AUTHORITIES_KEY, authorities)
            .signWith(key, SignatureAlgorithm.HS256)
            .setExpiration(validity)
            .compact()
    }

    fun validateToken(authToken: String?): Boolean {
        try {
            jwtParser!!.parseClaimsJws(authToken)
            return true
        } catch (e: ExpiredJwtException) {
            log.trace(INVALID_JWT_TOKEN, e)
        } catch (e: UnsupportedJwtException) {
            log.trace(INVALID_JWT_TOKEN, e)
        } catch (e: MalformedJwtException) {
            log.trace(INVALID_JWT_TOKEN, e)
        } catch (e: SignatureException) {
            log.trace(INVALID_JWT_TOKEN, e)
        } catch (e: IllegalArgumentException) {
            log.error("Token validation error {}", e.message)
        }
        return false
    }

    fun getAuthentication(token: String?): Authentication {
        val claims = jwtParser!!.parseClaimsJws(token).body
        val authorities: Collection<GrantedAuthority?> = Arrays
            .stream(claims[AUTHORITIES_KEY].toString().split(",".toRegex()).dropLastWhile { it.isEmpty() }
                .toTypedArray())
            .filter { auth: String -> auth.trim { it <= ' ' }.isNotEmpty() }
            .map { role: String? ->
                SimpleGrantedAuthority(
                    role
                )
            }
            .collect(Collectors.toList())
        val principal = User(claims.subject, "", authorities)
        return UsernamePasswordAuthenticationToken(principal, token, authorities)
    }
}