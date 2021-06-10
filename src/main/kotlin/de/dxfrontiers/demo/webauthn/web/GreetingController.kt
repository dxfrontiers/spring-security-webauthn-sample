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
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
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
class GreetingController(
    var webAuthnAuthenticatorManager: WebAuthnAuthenticatorManager,
    var registrationRequestValidator: WebAuthnRegistrationRequestValidator,
    var challengeRepository: ChallengeRepository,
    var userDetailsManager: UserDetailsManager,
    var passwordEncoder: PasswordEncoder
    ) {

    private val logger: Log = LogFactory.getLog(javaClass)
    private val authenticationTrustResolver: AuthenticationTrustResolver = AuthenticationTrustResolverImpl()

    @ModelAttribute
    fun addAttributes(model: Model, request: HttpServletRequest?) {
        val challenge = challengeRepository.loadOrGenerateChallenge(request)
        model.addAttribute("webAuthnChallenge", Base64UrlUtil.encodeToString(challenge.value))
        model.addAttribute("webAuthnCredentialIds", getCredentialIds())
    }

    @GetMapping
    fun greeting(model: Model): String{
        model.addAttribute("name", "Kenobi");
        return "greeting";
    }

    @GetMapping(value = ["/login"])
    fun login(): String? {
        return "login"
    }

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
        //result: BindingResult,
        model: Model,
        //redirectAttributes: RedirectAttributes
    ): String {

        val registrationRequestValidationResponse: WebAuthnRegistrationRequestValidationResponse
        registrationRequestValidationResponse = try {
            registrationRequestValidator.validate(
                request,
                userCreateForm.clientDataJSON,
                userCreateForm.attestationObject,
                userCreateForm.transports,
                userCreateForm.clientExtensions
            )
        } catch (e: WebAuthnException) {
            model.addAttribute(
                "errorMessage",
                "Authenticator registration request validation failed. Please try again."
            )
            logger.info("WebAuthn registration request validation failed.", e)
            return "VIEW_SIGNUP_SIGNUP"
        } catch (e: WebAuthnAuthenticationException) {
            model.addAttribute(
                "errorMessage",
                "Authenticator registration request validation failed. Please try again."
            )
            logger.info("WebAuthn registration request validation failed.", e)
            return "VIEW_SIGNUP_SIGNUP"
        }

        val password: String = passwordEncoder.encode(userCreateForm.password)

        val user = User(userCreateForm.username, password, listOf())

        println("stmt \t: ${registrationRequestValidationResponse.attestationObject.attestationStatement.format}")
        println("Data \t: ${Base64.getEncoder().encodeToString(
            registrationRequestValidationResponse.attestationObject.authenticatorData.attestedCredentialData?.credentialId
        )}")

        userDetailsManager.createUser(user)

        // wipe it
        user.eraseCredentials()
        println("After wipe: User: ${user.username}")

        val authenticator: WebAuthnAuthenticator = WebAuthnAuthenticatorImpl(
            "authenticator",
            user.username,
            registrationRequestValidationResponse.attestationObject.authenticatorData.attestedCredentialData,
            registrationRequestValidationResponse.attestationObject.attestationStatement,
            registrationRequestValidationResponse.attestationObject.authenticatorData.signCount,
            registrationRequestValidationResponse.transports,
            registrationRequestValidationResponse.registrationExtensionsClientOutputs,
            registrationRequestValidationResponse.attestationObject.authenticatorData.extensions
        )

        try {
            webAuthnAuthenticatorManager.createAuthenticator(authenticator)
        } catch (ex: IllegalArgumentException) {
            model.addAttribute("errorMessage", "Registration failed. The user may already be registered.")
            logger.info("Registration failed.", ex)
            return "VIEW_SIGNUP_SIGNUP"
        }
        logger.info("User registered: ${user.username}")
        return "/login"
    }

    @GetMapping(value = ["/signin"])
    fun signin(): String? {
        val authentication = SecurityContextHolder.getContext().authentication
        return if (authenticationTrustResolver.isAnonymous(authentication)) {
            "signin"
        } else {
            "signin-authenticator"
        }
    }

    fun getCredentialIds(): List<String>? {
        val authentication: Authentication = SecurityContextHolder.getContext().authentication
        val principal: Any = authentication.getPrincipal()
        return if (principal == null || authenticationTrustResolver.isAnonymous(authentication)) {
            emptyList()
        } else {
            try {
                val webAuthnAuthenticators = webAuthnAuthenticatorManager.loadAuthenticatorsByUserPrincipal(principal)
                webAuthnAuthenticators.stream()
                    .map { webAuthnAuthenticator: WebAuthnAuthenticator ->
                        Base64UrlUtil.encodeToString(
                            webAuthnAuthenticator.attestedCredentialData.credentialId
                        )
                    }
                    .collect(Collectors.toList())
            } catch (e: PrincipalNotFoundException) {
                emptyList()
            }
        }
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