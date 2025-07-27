package crypto

import (
	"bytes"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"log"
)

// openTPM is a function variable that can be replaced by a simulator in tests.
var openTPM = func(path string) (transport.TPMCloser, error) {
	rwc, err := tpmutil.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM device %q: %v", path, err)
	}
	return transport.FromReadWriteCloser(rwc), nil
}

// TPM represents a TPM device with its configuration
type TPM struct {
	devicePath string
	handle     uint32
	rwr        transport.TPMCloser // The opened TPM connection
}

// OpenTPM opens a TPM connection and returns a TPM instance.
func OpenTPM(devicePath string, handle uint32) (*TPM, error) {
	tpm := &TPM{
		devicePath: devicePath,
		handle:     handle,
	}

	rwr, err := openTPM(tpm.devicePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM device %q: %w", tpm.devicePath, err)
	}

	tpm.rwr = rwr

	return tpm, nil
}

// Close closes the TPM connection
func (t *TPM) Close() error {
	if t.rwr == nil {
		return nil // Already closed or never opened
	}

	err := t.rwr.Close()
	t.rwr = nil
	return err
}

// TPM templates (primaryTemplate, rsaTemplate)
var (
	primaryTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}

	rsaTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              true,
			SignEncrypt:          true,
		},
		AuthPolicy: tpm2.TPM2BDigest{},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{
				Buffer: make([]byte, 256),
			},
		),
	}
)

func (t *TPM) InitKey() error {
	if t.rwr == nil {
		return fmt.Errorf("TPM is closed")
	}

	// Check if something already exists at the handle
	namePub, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(t.handle)}.Execute(t.rwr)
	if err == nil {
		// Something exists at the handle, check type
		c, err := namePub.OutPublic.Contents()
		if err != nil {
			return fmt.Errorf("failed to get public contents for handle %#x: %v", t.handle, err)
		}

		if c.Type != tpm2.TPMAlgRSA {
			return fmt.Errorf("persistent handle %#x already exists and is not an RSA key (type: %#x)", t.handle, c.Type)
		}

		return nil
	}

	primaryHandle, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(primaryTemplate),
	}.Execute(t.rwr)
	if err != nil {
		return fmt.Errorf("failed to create primary key: %v", err)
	}

	rsaHandle, err := tpm2.Create{
		ParentHandle: &tpm2.NamedHandle{
			Handle: primaryHandle.ObjectHandle,
			Name:   primaryHandle.Name,
		},
		InPublic: tpm2.New2B(rsaTemplate),
	}.Execute(t.rwr)
	if err != nil {
		return fmt.Errorf("failed to create RSA key: %v", err)
	}

	loadRsp, err := tpm2.Load{
		ParentHandle: &tpm2.NamedHandle{
			Handle: primaryHandle.ObjectHandle,
			Name:   primaryHandle.Name,
		},
		InPrivate: rsaHandle.OutPrivate,
		InPublic:  rsaHandle.OutPublic,
	}.Execute(t.rwr)
	if err != nil {
		return fmt.Errorf("can't load object %q: %v", t.devicePath, err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: loadRsp.ObjectHandle,
		}
		_, err := flushContextCmd.Execute(t.rwr)
		if err != nil {
			log.Fatalf("can't close TPM %q: %v", t.devicePath, err)
		}
	}()

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
		},
		PersistentHandle: tpm2.TPMHandle(t.handle),
	}.Execute(t.rwr)
	if err != nil {
		return fmt.Errorf("can't persist handle %#x at %#x: %w", loadRsp.ObjectHandle.HandleValue(), t.handle, err)
	}

	log.Printf("TPM key initialized and handle %#x persisted successfully.", t.handle)

	return nil
}

func (t *TPM) ClearKey() error {
	if t.rwr == nil {
		return fmt.Errorf("TPM is closed")
	}

	log.Println("Clearing TPM Key")
	namePub, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(t.handle)}.Execute(t.rwr)
	if err != nil {
		return fmt.Errorf("failed to read public for handle 0x%x: %v", t.handle, err)
	}

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(t.handle),
			Name:   namePub.Name,
		},
		PersistentHandle: tpm2.TPMHandle(t.handle),
	}.Execute(t.rwr)
	if err != nil {
		return fmt.Errorf("failed to evict handle 0x%x: %v", t.handle, err)
	}

	log.Printf("TPM key at handle 0x%x cleared successfully.", t.handle)
	return nil
}

func (t *TPM) Encrypt(data []byte) ([]byte, error) {
	if t.rwr == nil {
		return nil, fmt.Errorf("TPM is not open, call OpenTPM() first")
	}

	rsaHandle := tpmutil.Handle(t.handle)
	result, err := tpm2.RSAEncrypt{
		KeyHandle: tpm2.TPMHandle(rsaHandle),
		Message:   tpm2.TPM2BPublicKeyRSA{Buffer: data},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}.Execute(t.rwr)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data with TPM: %v", err)
	}
	return result.OutData.Buffer, nil
}

func (t *TPM) Decrypt(data []byte) ([]byte, error) {
	if t.rwr == nil {
		return nil, fmt.Errorf("TPM is closed")
	}

	rsaHandle := tpmutil.Handle(t.handle)
	name, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(t.handle)}.Execute(t.rwr)
	if err != nil {
		return nil, fmt.Errorf("failed to read public for handle 0x%x: %v", t.handle, err)
	}
	result, err := tpm2.RSADecrypt{
		KeyHandle: &tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(rsaHandle),
			Name:   name.Name,
		},
		CipherText: tpm2.TPM2BPublicKeyRSA{Buffer: data},
		InScheme: tpm2.TPMTRSADecrypt{
			Scheme: tpm2.TPMAlgOAEP,
			Details: tpm2.NewTPMUAsymScheme(
				tpm2.TPMAlgOAEP,
				&tpm2.TPMSEncSchemeOAEP{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
	}.Execute(t.rwr)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with TPM (device %s, handle %#x): %v", t.devicePath, t.handle, err)
	}
	return result.Message.Buffer, nil
}

func (t *TPM) ValidateKey() error {
	if t.rwr == nil {
		return fmt.Errorf("TPM is closed")
	}

	log.Println("Validating TPM key usability...")
	testData := []byte("test encryption")
	encryptedData, err := t.Encrypt(testData)
	if err != nil {
		return fmt.Errorf("failed to encrypt test data with TPM key: %w", err)
	}
	decryptedData, err := t.Decrypt(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt test data with TPM key: %w", err)
	}
	if !bytes.Equal(testData, decryptedData) {
		return fmt.Errorf("decrypted test data does not match original")
	}
	log.Println("TPM key validation successful.")
	return nil
}
