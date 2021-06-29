package io.connorwyatt.springbff.auth

import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component

@Component
class AuthService(private val authenticationManager: AuthenticationManager) {
  fun login(credentials: LoginCredentials): AuthResult {
    val securityContext = SecurityContextHolder.getContext()

    if (securityContext.authentication?.isAuthenticated == true && securityContext.authentication.principal is UserInfo) {
      return AuthResult.alreadyLoggedIn()
    }

    return try {
      val authentication = authenticationManager.authenticate(
        UsernamePasswordAuthenticationToken(
          credentials.username,
          credentials.password
        )
      )

      val userInfo = authentication.principal as? UserInfo ?: throw Exception("Principal was not UserInfo")

      securityContext.authentication = authentication

      AuthResult.success(userInfo)
    } catch (e: Exception) {
      AuthResult.badCredentials()
    }
  }

  fun logout() {
    val securityContext = SecurityContextHolder.getContext()

    securityContext.authentication = null
  }
}
