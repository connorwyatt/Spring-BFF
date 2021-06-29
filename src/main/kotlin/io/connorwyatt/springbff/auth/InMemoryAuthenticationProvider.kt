package io.connorwyatt.springbff.auth

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Component

@Component
class InMemoryAuthenticationProvider : AuthenticationProvider {
  private val users = listOf(
    UserInfo("connor", "password", mutableListOf(SimpleGrantedAuthority("User")))
  )

  @Throws(AuthenticationException::class)
  override fun authenticate(authentication: Authentication): Authentication {
    val user = users.singleOrNull { it.username == authentication.name } ?: throw UsernameNotFoundException("")

    return UsernamePasswordAuthenticationToken(user, user.password, user.authorities)
  }

  override fun supports(authentication: Class<*>): Boolean {
    return UsernamePasswordAuthenticationToken::class.java.isAssignableFrom(authentication)
  }
}
