package io.connorwyatt.springbff.users

import io.connorwyatt.springbff.auth.UserInfo
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import java.security.Principal

@RestController
class UsersController {
  @GetMapping("/users/self")
  fun getSelfUser(principal: Principal): ResponseEntity<UserInfo> {
    return ResponseEntity.ok().body((principal as UsernamePasswordAuthenticationToken).principal as UserInfo)
  }
}
