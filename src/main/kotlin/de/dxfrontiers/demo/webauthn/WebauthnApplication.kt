package de.dxfrontiers.demo.webauthn

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class WebauthnApplication

fun main(args: Array<String>) {
	runApplication<WebauthnApplication>(*args)
}
