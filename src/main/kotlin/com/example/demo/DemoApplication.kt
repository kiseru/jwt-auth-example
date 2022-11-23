package com.example.demo

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.core.annotation.Order
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.config.web.servlet.invoke
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.server.ResponseStatusException
import java.time.Instant
import java.time.temporal.ChronoUnit
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@SpringBootApplication
class DemoApplication {

    @Bean
    @Order(2)
    fun securityFilterChain(http: HttpSecurity, jwtFilter: JwtFilter): SecurityFilterChain {
        http {
            csrf {
                disable()
            }
            authorizeRequests {
                authorize("/sign-in", anonymous)
                authorize(anyRequest, authenticated)
            }
            sessionManagement {
                sessionCreationPolicy = SessionCreationPolicy.STATELESS
            }
        }
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter::class.java)
        return http.build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Bean
    fun userDetailsService(passwordEncoder: PasswordEncoder): UserDetailsService {
        return InMemoryUserDetailsManager(
            User.withUsername("admin")
                .password(passwordEncoder.encode("qweasdzxc"))
                .roles("USER", "ADMIN")
                .build()
        )
    }

    @Bean
    fun jwtVerifier(algorithm: Algorithm): JWTVerifier = JWT.require(algorithm)
        .build()

    @Bean
    fun algorithm(): Algorithm = Algorithm.HMAC256("secret")
}

fun main(args: Array<String>) {
    runApplication<DemoApplication>(*args)
}

@RestController
class HomeController(
    private val passwordEncoder: PasswordEncoder,
    private val tokenService: TokenService,
    private val userDetailsService: UserDetailsService,
) {

    private val cars = listOf("Lada", "Audi", "BMW", "Volkswagen", "Skoda", "Honda")

    @GetMapping("/cars")
    fun findAllCars(): List<Car> {
        return cars.map { Car(it) }
    }

    @PostMapping("/sign-in")
    fun signIn(@RequestBody signInDto: SignInDto): TokenDto {
        val username = signInDto.username
        val user = userDetailsService.loadUserByUsername(username)
            ?: throw UsernameNotFoundException("User with $username not found")


        if (!passwordEncoder.matches(signInDto.password, user.password)) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST)
        }

        return TokenDto(tokenService.generateTokenFor(user))
    }
}

@Component
class JwtFilter(
    private val userDetailsService: UserDetailsService,
    private val tokenService: TokenService,
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authorization = request.getHeader(HttpHeaders.AUTHORIZATION)
        if (authorization == null || authorization.isEmpty() || !authorization.startsWith("Bearer ")) {
            filterChain.doFilter(request, response)
            return
        }

        val token = authorization.substring(7)
        val username = tokenService.getUsername(token)
        val user = userDetailsService.loadUserByUsername(username)
        val authentication =
            UsernamePasswordAuthenticationToken(user, null, user?.authorities ?: listOf())
        authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
        SecurityContextHolder.getContext().authentication = authentication
        filterChain.doFilter(request, response)
    }
}

@Service
class TokenService(
    private val algorithm: Algorithm,
    private val jwtVerifier: JWTVerifier,
) {

    fun generateTokenFor(user: UserDetails): String {
        return JWT.create()
            .withSubject(user.username)
            .withArrayClaim("roles", user.authorities.map { it.authority }.toTypedArray())
            .withExpiresAt(Instant.now().plus(15, ChronoUnit.MINUTES))
            .sign(algorithm)
    }

    fun getUsername(token: String): String {
        return jwtVerifier.verify(token).subject
    }
}

class Car(val name: String)

class SignInDto(
    val username: String,
    val password: String,
)

class TokenDto(
    val token: String,
)