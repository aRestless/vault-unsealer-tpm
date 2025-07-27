package vault

import (
	"context"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"log"
	"time"
)

type Vault struct {
	client        *api.Client
	tpmDevicePath string
	tpmHandle     uint32
}

type InitResult struct {
	RootToken string
	Keys      []string
}

type CreateAdminAppRoleResult struct {
	RoleID   string
	SecretID string
}

type InitConfig struct {
	InitKeyShares    int
	InitKeyThreshold int
}

type KeyStore interface {
	ReadKeys() ([]string, error)
}

func NewVault(vaultConfig *api.Config) (*Vault, error) {
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	return &Vault{
		client: client,
	}, nil
}

func (v *Vault) Initialize(cfg InitConfig) (*InitResult, error) {
	log.Println("Initializing Vault...")
	initReq := &api.InitRequest{
		SecretShares:    cfg.InitKeyShares,
		SecretThreshold: cfg.InitKeyThreshold,
	}
	resp, err := v.client.Sys().Init(initReq)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Vault: %w", err)
	}

	return &InitResult{
		RootToken: resp.RootToken,
		Keys:      resp.Keys,
	}, nil
}

func (v *Vault) IsInitialized() (bool, error) {
	return v.client.Sys().InitStatus()
}

func (v *Vault) UnsealLoop(ctx context.Context, store KeyStore) error {
	log.Println("Starting unsealing loop...")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping Unseal loop.")
			return ctx.Err()
		case <-ticker.C:
			sealStatus, err := v.client.Sys().SealStatus()
			if err != nil {
				log.Printf("Error checking Vault seal status: %v", err)
				continue
			}

			if sealStatus.Sealed {
				log.Println("Vault is sealed. Attempting to Unseal...")
				unsealed, err := v.Unseal(store)
				if err != nil {
					log.Printf("Failed to Unseal Vault: %v", err)
				} else {
					log.Println("Vault Unseal attempt completed.")
					if unsealed {
						log.Println("Vault is now unsealed.")
					} else {
						log.Println("Vault remains sealed after Unseal attempts.")
					}
				}
			}
		}
	}
}

func (v *Vault) Unseal(store KeyStore) (bool, error) {
	keys, err := store.ReadKeys()
	if err != nil {
		return false, fmt.Errorf("failed to read Unseal keys: %v", err)
	}

	if len(keys) == 0 {
		return false, errors.New("no Unseal keys available")
	}

	for i, key := range keys {
		status, err := v.client.Sys().Unseal(key)
		if err != nil {
			return false, fmt.Errorf("submitting Unseal key %d: %v", i, err)
		}

		if !status.Sealed {
			log.Println("Vault successfully unsealed.")
			return true, nil // Stop sending keys if unsealed
		}
	}

	return false, nil
}

// CreateAdminAppRole uses the root token to create an admin policy and AppRole,
// saves the encrypted secret ID, and revokes the root token.
func (v *Vault) CreateAdminAppRole(adminRoleID string, rootToken string) (*CreateAdminAppRoleResult, error) {
	log.Println("Using root token to create admin AppRole...")
	v.client.SetToken(rootToken)
	defer v.client.ClearToken()

	// 1. Create admin policy
	adminPolicy := `path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }`
	log.Println("Creating admin policy...")
	if err := v.client.Sys().PutPolicy("admin", adminPolicy); err != nil {
		return nil, fmt.Errorf("failed to create admin policy: %w", err)
	}

	// 2. Enable AppRole auth backend if not already enabled
	auths, err := v.client.Sys().ListAuth()
	if err != nil {
		return nil, fmt.Errorf("failed to list auth backends: %w", err)
	}
	if _, ok := auths["approle/"]; !ok {
		log.Println("Enabling AppRole auth backend...")
		if err := v.client.Sys().EnableAuthWithOptions("approle", &api.EnableAuthOptions{Type: "approle"}); err != nil {
			return nil, fmt.Errorf("failed to enable approle auth backend: %w", err)
		}
	}

	// 3. Create admin AppRole
	log.Printf("Creating admin AppRole with role ID: %s", adminRoleID)
	_, err = v.client.Logical().Write(fmt.Sprintf("auth/approle/role/%s", adminRoleID), map[string]interface{}{
		"policies": []string{"admin"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create admin approle: %w", err)
	}

	// 4. Generate the Secret ID
	secretIDResp, err := v.client.Logical().Write(fmt.Sprintf("auth/approle/role/%s/secret-id", adminRoleID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret id: %w", err)
	}
	secretID := secretIDResp.Data["secret_id"].(string)

	return &CreateAdminAppRoleResult{
		RoleID:   adminRoleID,
		SecretID: secretID,
	}, nil
}

func (v *Vault) RevokeToken(token string) error {
	log.Printf("Revoking token %s...", token)
	if err := v.client.Auth().Token().RevokeSelf(token); err != nil {
		return fmt.Errorf("failed to revoke token %s: %w", token, err)
	}
	log.Println("Token revoked successfully.")
	return nil
}
