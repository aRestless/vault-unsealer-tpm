package vault

import (
	"encoding/json"
	"fmt"
	"github.com/aRestless/vault-unsealer-tpm/config"
	"github.com/aRestless/vault-unsealer-tpm/crypto"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const (
	testDevicePath = "/dev/tpmrm0"
	testKeyHandle  = 0x81010002 // Using a different handle for testing
)

// newTestVaultServer creates a mock Vault server for testing.
func newTestVaultServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	// Mock for initialization
	mux.HandleFunc("/v1/sys/init", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT for init, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(&api.InitResponse{
			Keys:      []string{"key1", "key2", "key3", "key4", "key5"},
			RootToken: "test-root-token",
		})
	})

	// Mock for unsealing
	unsealProgress := 0
	mux.HandleFunc("/v1/sys/unseal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT for Unseal, got %s", r.Method)
		}
		unsealProgress++
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(&api.SealStatusResponse{
			Sealed:   unsealProgress < 3, // Unseals after 3 keys
			Progress: unsealProgress,
		})
	})

	// Mock for policy creation
	mux.HandleFunc("/v1/sys/policies/acl/admin", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT for policy creation, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Mock for enabling AppRole
	mux.HandleFunc("/v1/sys/auth/approle", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST for enabling approle, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Mock for creating AppRole
	mux.HandleFunc("/v1/auth/approle/role/test-admin", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT for creating approle, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Mock for generating Secret ID
	mux.HandleFunc("/v1/auth/approle/role/test-admin/secret-id", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected PUT for secret id, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(&api.Secret{
			Data: map[string]interface{}{
				"secret_id": "test-secret-id",
			},
		})
	})

	// Mock for revoking root token
	mux.HandleFunc("/v1/auth/token/revoke-self", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("Expected POST for token revoke, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Mock for listing auth backends
	mux.HandleFunc("/v1/sys/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET for listing auth backends, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"approle/": map[string]interface{}{
				"type": "approle",
			},
		})
	})

	return httptest.NewServer(mux)
}

func TestInitializeVault(t *testing.T) {
	server := newTestVaultServer(t)
	defer server.Close()

	v, err := NewVault(&api.Config{Address: server.URL})
	require.NoError(t, err)

	tempDir := t.TempDir()
	err = os.Chdir(tempDir)
	require.NoError(t, err)

	cfg := config.Config{
		TPMDevicePath:      testDevicePath,
		TPMHandle:          testKeyHandle,
		InitAdminRoleID:    "test-admin",
		InitKeyShares:      5,
		InitKeySharesSaved: 3,
		InitKeyThreshold:   3,
	}

	initResult, err := v.Initialize(InitConfig{
		InitKeyShares:    cfg.InitKeyShares,
		InitKeyThreshold: cfg.InitKeyThreshold,
	})
	require.NoError(t, err)

	assert.Equal(t, 5, len(initResult.Keys))
	assert.Equal(t, "test-root-token", initResult.RootToken)
	for i, key := range initResult.Keys {
		assert.Equal(t, fmt.Sprintf("key%d", i+1), key)
	}
}

func TestUnsealVault(t *testing.T) {
	server := newTestVaultServer(t)
	defer server.Close()

	v, err := NewVault(&api.Config{Address: server.URL})
	require.NoError(t, err)

	tempDir := t.TempDir()
	err = os.Chdir(tempDir)
	require.NoError(t, err)

	cfg := config.Config{
		TPMDevicePath: testDevicePath, // Use simulator
		TPMHandle:     testKeyHandle,
	}

	tpm, err := crypto.OpenTPM(cfg.TPMDevicePath, uint32(cfg.TPMHandle))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, tpm.Close())
	}()

	// Pre-create encrypted keys
	require.NoError(t, tpm.InitKey())
	defer func() {
		require.NoError(t, tpm.ClearKey())
	}()

	var keys []string
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("key%d", i+1)
		keys = append(keys, key)
		encrypted, err := tpm.Encrypt([]byte(key))
		require.NoError(t, err)
		err = os.WriteFile(fmt.Sprintf("Unseal-key-%d.enc", i), encrypted, 0600)
		require.NoError(t, err)
	}

	store := &crypto.KeyStore{
		GlobPattern:   "Unseal-key-*.enc",
		TPMDevicePath: cfg.TPMDevicePath,
		TPMHandle:     uint32(cfg.TPMHandle),
	}

	unsealed, err := v.Unseal(store)
	assert.NoError(t, err)
	assert.True(t, unsealed)
}

func TestCreateAdminAppRole(t *testing.T) {
	server := newTestVaultServer(t)
	defer server.Close()

	v, err := NewVault(&api.Config{Address: server.URL})
	require.NoError(t, err)

	tempDir := t.TempDir()
	err = os.Chdir(tempDir)
	require.NoError(t, err)

	cfg := config.Config{
		TPMDevicePath:   testDevicePath,
		TPMHandle:       testKeyHandle,
		InitAdminRoleID: "test-admin",
	}

	tpm, err := crypto.OpenTPM(cfg.TPMDevicePath, uint32(cfg.TPMHandle))
	require.NoError(t, err)
	defer func() {
		require.NoError(t, tpm.Close())
	}()

	require.NoError(t, tpm.InitKey())
	defer func() {
		require.NoError(t, tpm.ClearKey())
	}()

	result, err := v.CreateAdminAppRole(cfg.InitAdminRoleID, "test-root-token")
	require.NoError(t, err)
	assert.Equal(t, "test-admin", result.RoleID)
	assert.Equal(t, "test-secret-id", result.SecretID)
}
