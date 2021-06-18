package de.dxfrontiers.demo.webauthn.web

import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidationResponse
import com.webauthn4j.springframework.security.WebAuthnRegistrationRequestValidator
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticator
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorImpl
import com.webauthn4j.springframework.security.authenticator.WebAuthnAuthenticatorManager
import com.webauthn4j.springframework.security.challenge.ChallengeRepository
import com.webauthn4j.springframework.security.exception.PrincipalNotFoundException
import com.webauthn4j.springframework.security.exception.WebAuthnAuthenticationException
import com.webauthn4j.util.Base64UrlUtil
import com.webauthn4j.util.UUIDUtil
import com.webauthn4j.util.exception.WebAuthnException
import org.apache.commons.logging.Log
import org.apache.commons.logging.LogFactory
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.UserDetailsManager
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.ModelAttribute
import org.springframework.web.bind.annotation.PostMapping
import java.util.*
import java.util.stream.Collectors
import javax.servlet.http.HttpServletRequest


@Controller
class WebAuthnController(
    var webAuthnAuthenticatorManager: WebAuthnAuthenticatorManager,
    var registrationRequestValidator: WebAuthnRegistrationRequestValidator,
    var userDetailsManager: UserDetailsManager,
    var passwordEncoder: PasswordEncoder
    ) {

    private val logger: Log = LogFactory.getLog(javaClass)
    private val authenticationTrustResolver: AuthenticationTrustResolver = AuthenticationTrustResolverImpl()


    @GetMapping(value = ["/signup"])
    fun template(model: Model): String? {
        val userHandle = UUID.randomUUID()
        val userHandleStr = Base64UrlUtil.encodeToString(UUIDUtil.convertUUIDToBytes(userHandle))
        val userCreateForm = UserCreateForm(userHandleStr)
        model.addAttribute("userForm", userCreateForm)
        return "signup"
    }

    @PostMapping(value = ["/signup"])
    fun create(
        request: HttpServletRequest,
        @ModelAttribute("userForm") userCreateForm: UserCreateForm,
        model: Model,
    ): String {
        val validationResponse: WebAuthnRegistrationRequestValidationResponse = try {
            registrationRequestValidator.validate(
                request,
                userCreateForm.clientDataJSON,
                userCreateForm.attestationObject,
                userCreateForm.transports,
                userCreateForm.clientExtensions
            )
        } catch (e: WebAuthnException) {
            logger.info("WebAuthn registration request validation failed.", e)
            return "signup"
        } catch (e: WebAuthnAuthenticationException) {
            logger.info("WebAuthn registration request validation failed.", e)
            return "signup"
        }

        val password: String = passwordEncoder.encode(userCreateForm.password)
        val user = User(userCreateForm.username, password, listOf())
        userDetailsManager.createUser(user)

        logger.info("att: ${validationResponse.attestationObject.attestationStatement.format}")

        val authenticator: WebAuthnAuthenticator = WebAuthnAuthenticatorImpl(
            "authenticator",
            user.username,
            validationResponse.attestationObject.authenticatorData.attestedCredentialData,
            validationResponse.attestationObject.attestationStatement,
            validationResponse.attestationObject.authenticatorData.signCount,
            validationResponse.transports,
            validationResponse.registrationExtensionsClientOutputs,
            validationResponse.attestationObject.authenticatorData.extensions
        )

        try {
            webAuthnAuthenticatorManager.createAuthenticator(authenticator)
        } catch (ex: IllegalArgumentException) {
            logger.info("Registration failed.", ex)
            return "signup"
        }
        logger.info("User registered: ${user.username}")
        return "/signin"
    }

    @GetMapping(value = ["/signin"])
    fun signin(model: Model): String? {
        val authentication = SecurityContextHolder.getContext().authentication
        return if (authenticationTrustResolver.isAnonymous(authentication)) {
            "signin"
        } else {
            model.addAttribute("name", authentication.name);
            "signin-authenticator"
        }
    }

    @GetMapping
    fun greeting(model: Model): String{
        val name = SecurityContextHolder.getContext().authentication.name
        model.addAttribute("name", name);
        return "greeting";
    }

}

data class UserCreateForm (
    var userHandle: String = "",
    var username: String = "",
    var password: String = "",
    var clientDataJSON: String = "",
    var attestationObject: String = "",
    var clientExtensions: String = "",
    var transports: Set<String> = setOf(),

)