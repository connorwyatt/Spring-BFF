package io.connorwyatt.springbff.auth

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.web.context.SaveContextOnUpdateOrErrorResponseWrapper
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class SaveToCookieResponseWrapper(
  private val request: HttpServletRequest,
  response: HttpServletResponse,
  private val cookieHmacKey: String,
  private val objectMapper: ObjectMapper
) : SaveContextOnUpdateOrErrorResponseWrapper(response, true) {
  public override fun saveContext(securityContext: SecurityContext) {
    val response = response as HttpServletResponse
    val authentication: Authentication? = securityContext.authentication

    val requestCookie = request.cookies?.singleOrNull { it.name == SignedUserInfoCookie.NAME }

    if (authentication == null) {
      if (requestCookie != null) {
        response.addCookie(SignedUserInfoCookie.unset().apply { secure = request.isSecure })
      }
      return
    }

    if (authentication.principal !is UserInfo) {
      return
    }

    val userInfo: UserInfo = authentication.principal as UserInfo
    val cookie = SignedUserInfoCookie(userInfo, cookieHmacKey, objectMapper).apply { secure = request.isSecure }

    response.addCookie(cookie)
  }
}
