package crypto

import (
	"bytes"
	"testing"
)

const (
	testDevicePath = "/dev/tpmrm0"
	testKeyHandle  = 0x81010003 // Using a different handle for testing
)

func TestTPMIntegration(t *testing.T) {
	tpm, err := OpenTPM(testDevicePath, testKeyHandle)
	if err != nil {
		t.Fatalf("NewTPM failed: %v", err)
	}

	t.Run("TestInitTPMKey", func(t *testing.T) {
		err := tpm.InitKey()
		if err != nil {
			t.Fatalf("InitKey failed: %v", err)
		}
		defer tpm.ClearKey()
	})

	t.Run("TestEncryptDecrypt", func(t *testing.T) {
		if err := tpm.InitKey(); err != nil {
			t.Fatalf("pre-test setup: InitKey failed: %v", err)
		}
		defer tpm.ClearKey()

		secretMessage := []byte("this is a very secret message")
		encrypted, err := tpm.Encrypt(secretMessage)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		if len(encrypted) == 0 {
			t.Fatal("Encrypt returned empty byte slice")
		}
		decrypted, err := tpm.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if !bytes.Equal(secretMessage, decrypted) {
			t.Errorf("decrypted message did not match original secret")
			t.Logf("Original:  %s", secretMessage)
			t.Logf("Decrypted: %s", decrypted)
		}
	})
}
