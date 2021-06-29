package io.connorwyatt.springbff.auth

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class UserInfo(
  private val username: String,
  private val password: String?,
  private val authorities: MutableCollection<out GrantedAuthority>
) :
  UserDetails {
  constructor(username: String, authorities: MutableCollection<out GrantedAuthority>) : this(username, "", authorities)

  override fun getAuthorities() = authorities

  override fun getPassword() = password

  override fun getUsername() = username

  override fun isAccountNonExpired() = true

  override fun isAccountNonLocked() = true

  override fun isCredentialsNonExpired() = true

  override fun isEnabled() = true
}
