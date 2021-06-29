package io.connorwyatt.springbff.filters

import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component
import java.io.IOException
import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletRequestWrapper

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class XmlHttpRequestFilter : Filter {
  @Throws(IOException::class, ServletException::class)
  override fun doFilter(
    request: ServletRequest,
    response: ServletResponse?,
    chain: FilterChain
  ) {
    (request as HttpServletRequest?)?.let {
      val reqWrapper: HttpServletRequestWrapper = object : HttpServletRequestWrapper(it) {
        override fun getHeader(name: String): String {
          return if (name == "X-Requested-With") {
            "XMLHttpRequest"
          } else super.getHeader(name)
        }
      }
      chain.doFilter(reqWrapper, response)
      return
    }

    chain.doFilter(request, response)
  }
}
