package crypto

import (
	"fmt"
	"os"
	"path/filepath"
)

// KeyStore is a KeyStore implementation that reads keys encrypted by a TPM.
type KeyStore struct {
	GlobPattern   string
	TPMDevicePath string
	TPMHandle     uint32
}

// ReadKeys reads all unseal-key-*.enc files in the store directory, decrypts them with the TPM,
// and returns the unseal keys.
func (s *KeyStore) ReadKeys() ([]string, error) {
	tpm, err := OpenTPM(s.TPMDevicePath, s.TPMHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	files, err := filepath.Glob(s.GlobPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to list key files: %w", err)
	}

	var keys []string
	for _, file := range files {
		encryptedKey, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", file, err)
		}
		decryptedKey, err := tpm.Decrypt(encryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key %s: %w", file, err)
		}
		keys = append(keys, string(decryptedKey))
	}
	return keys, nil
}
