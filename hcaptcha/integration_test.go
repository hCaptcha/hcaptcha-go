package hcaptcha

import (
	"os"
	"testing"
)

func TestLiveSiteverify(t *testing.T) {
	if os.Getenv("HCAPTCHA_LIVE_TEST") != "1" {
		t.Skip("set HCAPTCHA_LIVE_TEST=1 to call the real Siteverify endpoint")
	}
	verifier, err := New("0x0000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	result, err := verifier.Verify("10000000-aaaa-bbbb-cccc-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if result["success"] != true {
		t.Fatalf("Siteverify rejected documented public test token: %+v", result)
	}
}
