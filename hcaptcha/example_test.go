package hcaptcha_test

import (
	"context"
	"log"
	"os"

	hcaptcha "github.com/hCaptcha/hcaptcha-go/hcaptcha"
)

func ExampleClient_Verify() {
	secret := os.Getenv("HCAPTCHA_SECRET")
	token := "response token from the application request"
	verifier, err := hcaptcha.New(secret)
	if err != nil {
		log.Fatalf("hcaptcha init failed: %v", err)
	}

	result, err := verifier.Verify(token)
	if err != nil || result["success"] != true {
		// Fail closed: do not continue with the protected action.
		return
	}
	// Continue with the protected action.
}

func ExampleClient_VerifyRequest() {
	verifier, err := hcaptcha.New(os.Getenv("HCAPTCHA_SECRET"))
	if err != nil {
		log.Fatalf("hcaptcha init failed: %v", err)
	}
	result, err := verifier.VerifyRequest(context.Background(), hcaptcha.Request{
		Token:    "response token from the application request",
		RemoteIP: "203.0.113.1",
		SiteKey:  "expected sitekey UUID",
	})
	if err != nil || result["success"] != true {
		return
	}
}
