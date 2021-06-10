package de.dxfrontiers.demo.webauthn.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator
import com.webauthn4j.springframework.security.WebAuthnSecurityExpression
import com.webauthn4j.springframework.security.authenticator.InMemoryWebAuthnAuthenticatorManager
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorService
import com.webauthn4j.springframework.security.challenge.ChallengeRepository
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository
import com.webauthn4j.springframework.security.config.configurers.WebAuthnAuthenticationProviderConfigurer
import com.webauthn4j.springframework.security.config.configurers.WebAuthnLoginConfigurer
import com.webauthn4j.springframework.security.converter.jackson.WebAuthn4JSpringSecurityJSONModule
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException
import com.webauthn4j.springframework.security.options.*
import com.webauthn4j.springframework.security.server.ServerPropertyProvider
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.provisioning.UserDetailsManager
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import java.util.*
import java.util.stream.Collectors
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


@Configuration
@EnableWebSecurity
class SecurityConfiguration(
    var webAuthnAuthenticatorService: WebAuthnAuthenticatorService,
    var webAuthnManager: WebAuthnManager,
    var passwordEncoder: PasswordEncoder,
    var userDetailsService : UserDetailsService
) : WebSecurityConfigurerAdapter() {

    @Throws(Exception::class)
    override fun configure(builder: AuthenticationManagerBuilder) {
        builder.apply(WebAuthnAuthenticationProviderConfigurer(webAuthnAuthenticatorService, webAuthnManager))
        builder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder)
    }
    override fun configure(web: WebSecurity) {
        // ignore static resources
        web.ignoring().antMatchers(
            "/favicon.ico",
            "/js/**",
            "/css/**",
            "/webjars/**"
        )
    }

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {

        http.apply(WebAuthnLoginConfigurer.webAuthnLogin())
            .defaultSuccessUrl("/", true)
            .attestationOptionsEndpoint()
                .rp().name("WebAuthn Sample").and()
                .pubKeyCredParams(
                    PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256)
                ).and()
            .assertionOptionsEndpoint()

        // Authorization
        http.authorizeRequests()
//            .mvcMatchers(HttpMethod.GET, "/login").permitAll()
            .mvcMatchers(HttpMethod.GET, "/signin").permitAll()
            .mvcMatchers(HttpMethod.GET, "/signup").permitAll()
            .mvcMatchers(HttpMethod.POST, "/signup").permitAll()
            .anyRequest()
                .access("@webAuthnSecurityExpression.isWebAuthnAuthenticated(authentication)")

        // for routing the user to the correct endpoints
        http.exceptionHandling()
            .accessDeniedHandler { _: HttpServletRequest?, response: HttpServletResponse, _: AccessDeniedException? ->
                response.sendRedirect("/signin")
            }
            .authenticationEntryPoint { _: HttpServletRequest, httpServletResponse: HttpServletResponse, _: AuthenticationException ->
                httpServletResponse.sendRedirect("/signin")
            }

        // As WebAuthn has its own CSRF protection mechanism (challenge), CSRF token is disabled here
        http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
        http.csrf().ignoringAntMatchers("/webauthn/**")

    }

}

@Configuration
 class WebSecurityBeanConfig {
    @Bean
    fun passwordEncoder(): PasswordEncoder? {
        return BCryptPasswordEncoder()
    }

    @Bean
    fun userDetailsManager(): UserDetailsManager? {
        return InMemoryUserDetailsManager()
    }

    @Bean
    fun webAuthnAuthenticatorManager(): WebAuthnAuthenticatorManager? {
        return InMemoryWebAuthnAuthenticatorManager()
    }

    @Bean
    fun objectConverter(): ObjectConverter? {
        val jsonMapper = ObjectMapper()
        jsonMapper.registerModule(WebAuthnMetadataJSONModule())
        jsonMapper.registerModule(WebAuthn4JSpringSecurityJSONModule())
        val cborMapper = ObjectMapper(CBORFactory())
        return ObjectConverter(jsonMapper, cborMapper)
    }

    @Bean
    fun webAuthnManager(objectConverter: ObjectConverter?): WebAuthnManager? {
        return WebAuthnManager.createNonStrictWebAuthnManager(objectConverter!!)
    }

    @Bean
    fun webAuthnSecurityExpression(): WebAuthnSecurityExpression? {
        return WebAuthnSecurityExpression()
    }

    @Bean
    fun attestationOptionsProvider(
        rpIdProvider: RpIdProvider?,
        webAuthnAuthenticatorService: WebAuthnAuthenticatorService?,
        challengeRepository: ChallengeRepository?
    ): AttestationOptionsProvider? {
        return AttestationOptionsProviderImpl(rpIdProvider, webAuthnAuthenticatorService, challengeRepository)
    }

    @Bean
    fun rpIdProvider(): RpIdProvider? {
        return RpIdProviderImpl()
    }
    @Bean
    fun challengeRepository(): ChallengeRepository? {
        return HttpSessionChallengeRepository()
    }

    @Bean
    fun serverPropertyProvider(
        rpIdProvider: RpIdProvider?,
        challengeRepository: ChallengeRepository?
    ): ServerPropertyProvider? {
        return ServerPropertyProviderImpl(rpIdProvider, challengeRepository)
    }

    @Bean
    fun webAuthnRegistrationRequestValidator(
        webAuthnManager: WebAuthnManager?,
        serverPropertyProvider: ServerPropertyProvider?
    ): WebAuthnRegistrationRequestValidator? {
        return WebAuthnRegistrationRequestValidator(webAuthnManager, serverPropertyProvider)
    }
}
