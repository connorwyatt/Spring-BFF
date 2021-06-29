package io.connorwyatt.springbff.auth

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.convertValue
import com.fasterxml.jackson.module.kotlin.readValue
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.time.Duration
import java.time.Instant
import java.time.temporal.ChronoUnit.HOURS
import java.util.Base64
import java.util.regex.Matcher
import java.util.regex.Pattern
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.servlet.http.Cookie

class SignedUserInfoCookie : Cookie {
  private val objectMapper: ObjectMapper
  private val cookieHmacKey: String
  private val payload: SignedUserInfoCookiePayload
  private val serializedPayload: String

  constructor(userInfo: UserInfo, cookieHmacKey: String, objectMapper: ObjectMapper) : super(NAME, "") {
    path = PATH
    maxAge = Duration.of(1, HOURS).toSeconds().toInt()
    isHttpOnly = true

    this.objectMapper = objectMapper
    this.cookieHmacKey = cookieHmacKey

    val username = userInfo.username
    val roles = userInfo.authorities.map { obj: GrantedAuthority -> obj.authority }

    val hmac = calculateHmac(username, roles)

    payload = SignedUserInfoCookiePayload(username, roles, hmac)

    serializedPayload = Base64.getEncoder().encodeToString(objectMapper.writeValueAsBytes(payload))
  }

  constructor(cookie: Cookie, cookieHmacKey: String, objectMapper: ObjectMapper) : super(NAME, "") {
    path = cookie.path
    maxAge = cookie.maxAge
    isHttpOnly = cookie.isHttpOnly

    this.objectMapper = objectMapper
    this.cookieHmacKey = cookieHmacKey

    if (cookie.name != NAME) {
      throw IllegalArgumentException("No $NAME Cookie")
    }

    serializedPayload = String(Base64.getDecoder().decode(cookie.value))

    payload = objectMapper.readValue(serializedPayload)

    val hmac = calculateHmac(payload.username, payload.roles)

    if (hmac != payload.hmac){
      throw CookieVerificationFailedException("Cookie signature (HMAC) invalid")
    }
  }

  fun getUserInfo() = UserInfo(
    payload.username,
    payload.roles.map { SimpleGrantedAuthority(it) }.toMutableSet(),
  )

  override fun getValue() = serializedPayload

  private fun calculateHmac(username: String, roles: List<String>): String {
    val value = "$username:${roles.joinToString("|")}"
    return hash(value, cookieHmacKey)
  }

  private fun hash(value: String, secretKey: String): String {
    val secretKeyBytes = secretKey.toByteArray(StandardCharsets.UTF_8)
    val valueBytes = value.toByteArray(StandardCharsets.UTF_8)
    return try {
      val mac = Mac.getInstance(HMAC_SHA_512)
      val secretKeySpec = SecretKeySpec(secretKeyBytes, HMAC_SHA_512)
      mac.init(secretKeySpec)
      val hmacBytes = mac.doFinal(valueBytes)
      Base64.getEncoder().encodeToString(hmacBytes)
    } catch (e: NoSuchAlgorithmException) {
      throw RuntimeException(e)
    } catch (e: InvalidKeyException) {
      throw RuntimeException(e)
    }
  }

  companion object {
    val NAME = SignedUserInfoCookie::class.simpleName ?: throw NullPointerException()
    private const val PATH = "/"
    private const val HMAC_SHA_512 = "HmacSHA512"

    fun unset() = Cookie(NAME, "").apply {
      path = PATH
      maxAge = 0
      isHttpOnly = true
    }
  }
}
