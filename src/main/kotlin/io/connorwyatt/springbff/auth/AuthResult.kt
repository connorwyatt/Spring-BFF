package io.connorwyatt.springbff.auth

data class AuthResult(val success: Boolean, val userInfo: UserInfo? = null, val error: String? = null) {
  companion object {
    fun success(userInfo: UserInfo) = AuthResult(true, userInfo = userInfo)

    fun alreadyLoggedIn() = AuthResult(false, error = "Already logged in")

    fun badCredentials() = AuthResult(false, error = "Bad credentials")
  }
}
