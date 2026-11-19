package crypto

import "testing"

func TestRoundTrip(t *testing.T) {
	e, _ := NewEncrypter([]byte("key"))
	ct, err := e.Encrypt("hello")
	if err != nil {
		t.Fatal(err)
	}
	ct2, _ := e.Encrypt("hello")
	if ct == ct2 {
		t.Fatal("ciphertexts must differ (random nonce)")
	}
	pt, err := e.Decrypt(ct)
	if err != nil || pt != "hello" {
		t.Fatalf("got %q, %v", pt, err)
	}
	other, _ := NewEncrypter([]byte("other"))
	if _, err := other.Decrypt(ct); err == nil {
		t.Fatal("decrypt with wrong key must fail")
	}
}
