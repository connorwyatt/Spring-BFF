package io.connorwyatt.springbff.auth

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.BeanIds
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy.STATELESS

@Configuration
@EnableWebSecurity
class WebSecurityConfig(
  private val cookieSecurityContextRepository: CookieSecurityContextRepository,
  private val inMemoryAuthenticationProvider: InMemoryAuthenticationProvider,
  private val authenticationEntryPoint: UnauthorizedEntryPoint,
) : WebSecurityConfigurerAdapter() {
  @Throws(Exception::class)
  override fun configure(http: HttpSecurity) {
    http
      .sessionManagement().sessionCreationPolicy(STATELESS)
      .and().csrf().disable()

      .securityContext().securityContextRepository(cookieSecurityContextRepository)
      .and().logout().permitAll().deleteCookies(SignedUserInfoCookie.NAME)

      .and().authorizeRequests()
      .antMatchers("/auth/login").permitAll()
      .antMatchers("/**").authenticated()

      .and().exceptionHandling().authenticationEntryPoint(authenticationEntryPoint)
  }

  override fun configure(auth: AuthenticationManagerBuilder) {
    auth.authenticationProvider(inMemoryAuthenticationProvider)
  }

  @Bean(name = [BeanIds.AUTHENTICATION_MANAGER])
  @Throws(java.lang.Exception::class)
  override fun authenticationManagerBean(): AuthenticationManager {
    return super.authenticationManagerBean()
  }
}

