package io.connorwyatt.springbff.auth

data class SignedUserInfoCookiePayload(val username: String, val roles: List<String>, val hmac: String)
