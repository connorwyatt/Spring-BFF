package io.connorwyatt.springbff.auth

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import javax.servlet.http.HttpServletRequest

@RestController
class AuthController(private val authService: AuthService) {
  @PostMapping("/auth/login")
  fun login(@RequestBody credentials: LoginCredentials): ResponseEntity<Unit> {
    val result = authService.login(credentials)

    if (!result.success) {
      return ResponseEntity.badRequest().build()
    }

    return ResponseEntity.ok().build()
  }

  @PostMapping("/auth/logout")
  fun logout(): ResponseEntity<Unit> {
    authService.logout()

    return ResponseEntity.ok().build()
  }
}
