package io.connorwyatt.springbff.auth

import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.context.HttpRequestResponseHolder
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.stereotype.Component
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class CookieSecurityContextRepository(
  private val objectMapper: ObjectMapper,
  @param:Value("\${auth.cookie.hmac-key}") private val cookieHmacKey: String
) :
  SecurityContextRepository {
  private val logger = LoggerFactory.getLogger(CookieSecurityContextRepository::class.java)

  override fun loadContext(requestResponseHolder: HttpRequestResponseHolder): SecurityContext {
    requestResponseHolder.response =
      SaveToCookieResponseWrapper(
        requestResponseHolder.request,
        requestResponseHolder.response,
        cookieHmacKey,
        objectMapper
      )

    val context = SecurityContextHolder.createEmptyContext()

    readUserInfoFromCookie(requestResponseHolder.request)?.let {
      context.authentication = UsernamePasswordAuthenticationToken(it, null, it.authorities)
    }

    return context
  }

  override fun saveContext(context: SecurityContext, request: HttpServletRequest, response: HttpServletResponse) {
    val responseWrapper = response as? SaveToCookieResponseWrapper
    responseWrapper?.let {
      if (!it.isContextSaved) {
        it.saveContext(context)
      }
    }
  }

  override fun containsContext(request: HttpServletRequest): Boolean {
    return readUserInfoFromCookie(request) != null
  }

  private fun readUserInfoFromCookie(request: HttpServletRequest) = readCookieFromRequest(request)?.let {
    createUserInfo(it)
  }

  private fun readCookieFromRequest(request: HttpServletRequest): Cookie? {
    if (request.cookies == null) {
      logger.debug("No cookies in request")
      return null
    }

    val cookie: Cookie? = request.cookies.singleOrNull { c -> SignedUserInfoCookie.NAME == c.name }

    if (cookie == null) {
      logger.debug("No {} cookie in request", SignedUserInfoCookie.NAME)
    }

    return cookie
  }

  private fun createUserInfo(cookie: Cookie): UserInfo {
    return SignedUserInfoCookie(cookie, cookieHmacKey, objectMapper).getUserInfo()
  }
}
