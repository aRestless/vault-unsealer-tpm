package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aRestless/vault-unsealer-tpm/config"
	"github.com/aRestless/vault-unsealer-tpm/crypto"
	"github.com/aRestless/vault-unsealer-tpm/vault"
	"github.com/hashicorp/vault/api"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func run(cfg config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Create store path if it doesn't exist
	if err := os.MkdirAll(cfg.StorePath, 0700); err != nil {
		return fmt.Errorf("failed to create store path %s: %v", cfg.StorePath, err)
	}

	// Configure Vault client
	vaultConfig, err := getVaultConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to get Vault configuration: %v", err)
	}

	// Initialize TPM key
	log.Println("Initializing TPM...")
	err = initializeAndTestTPM(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize TPM: %v", err)
	}
	log.Println("TPM initialized.")

	v, err := vault.NewVault(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %v", err)
	}

	// Initialization check
	keyGlobPattern := filepath.Join(cfg.StorePath, "unseal-key-*.tpm.enc")
	keyFiles, err := filepath.Glob(keyGlobPattern)
	if err != nil {
		return fmt.Errorf("failed to check for unseal key files: %w", err)
	}

	if len(keyFiles) == 0 {
		log.Println("No unseal keys found. Initializing Vault...")
		err = initialize(ctx, v, keyGlobPattern, cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize Vault: %v", err)
		}
	}

	// Start the unsealing loop
	store := &crypto.KeyStore{
		GlobPattern:   keyGlobPattern,
		TPMDevicePath: cfg.TPMDevicePath,
		TPMHandle:     uint32(cfg.TPMHandle),
	}
	return v.UnsealLoop(ctx, store)
}

func initializeAndTestTPM(cfg config.Config) error {
	tpm, err := crypto.OpenTPM(cfg.TPMDevicePath, uint32(cfg.TPMHandle))
	if err != nil {
		return fmt.Errorf("failed to open TPM device: %v", err)
	}
	defer tpm.Close()

	if err := tpm.InitKey(); err != nil {
		return fmt.Errorf("failed to initialize TPM key: %v", err)
	}

	if err := tpm.ValidateKey(); err != nil {
		return fmt.Errorf("failed to validate TPM key: %v", err)
	}

	return nil
}

func getVaultConfig(cfg config.Config) (*api.Config, error) {
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = cfg.VaultAddress

	tlsConfig := &tls.Config{}
	if cfg.VaultTLSSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	if cfg.VaultTLSServerName != "" {
		tlsConfig.ServerName = cfg.VaultTLSServerName
	}

	if cfg.VaultTLSCACert != "" {
		caCert, err := os.ReadFile(cfg.VaultTLSCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}
	vaultConfig.HttpClient.Transport = &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return vaultConfig, nil
}

func initialize(ctx context.Context, v *vault.Vault, keyGlobPattern string, cfg config.Config) error {
	b, _ := json.Marshal(&cfg)
	log.Println(string(b))

	if cfg.InitRecoveryPubKey == "" {
		return fmt.Errorf("recovery public key must be provided for initialization")
	}
	recoveryPubKey, err := crypto.LoadPublicKey(cfg.InitRecoveryPubKey)
	if err != nil {
		return fmt.Errorf("failed to load recovery public key: %v", err)
	}

	if cfg.InitAdminRoleID == "" || cfg.InitAdminPubKey == "" {
		return fmt.Errorf("admin role ID or admin public key must be provided for initialization")
	}
	adminPubKey, err := crypto.LoadPublicKey(cfg.InitAdminPubKey)
	if err != nil {
		return fmt.Errorf("failed to load admin public key: %v", err)
	}

	for {
		log.Printf("Waiting for Vault ...")
		isInitialized, err := v.IsInitialized()
		if err == nil && isInitialized {
			return fmt.Errorf("Vault is already initialized.")
		}

		if err == nil && !isInitialized {
			break
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("initialization interrupted: %v", ctx.Err())
		case <-time.After(5 * time.Second):
		}
	}

	initResult, err := v.Initialize(vault.InitConfig{
		InitKeyShares:    cfg.InitKeyShares,
		InitKeyThreshold: cfg.InitKeyThreshold,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize Vault: %v", err)
	}

	err = storeKeys(cfg, initResult.Keys, recoveryPubKey)
	if err != nil {
		return fmt.Errorf("failed to store unseal keys: %v", err)
	}

	log.Println(cfg.TPMDevicePath, cfg.TPMHandle)
	store := &crypto.KeyStore{
		GlobPattern:   keyGlobPattern,
		TPMDevicePath: cfg.TPMDevicePath,
		TPMHandle:     uint32(cfg.TPMHandle),
	}

	unsealed := false
	for !unsealed {
		ticker := time.NewTicker(5 * time.Second)
		select {
		case <-ctx.Done():
			return fmt.Errorf("unsealing interrupted: %v", ctx.Err())
		case <-ticker.C:
			unsealed, err = v.Unseal(store)
			if err != nil {
				log.Printf("failed to unseal Vault, retrying: %v", err)
			}
		}
	}

	adminResult, err := v.CreateAdminAppRole(cfg.InitAdminRoleID, initResult.RootToken)
	if err != nil {
		return fmt.Errorf("failed to create admin approle: %w", err)
	}

	encryptedAdminSecret, err := crypto.EncryptWithRSA(adminPubKey, []byte(adminResult.SecretID))
	if err != nil {
		return fmt.Errorf("failed to encrypt token for role %s: %v", adminResult.RoleID, err)
	}
	fileName := fmt.Sprintf("secret-%s.admin.enc", cfg.InitAdminRoleID)
	path := filepath.Join(cfg.StorePath, fileName)
	log.Printf("saving encrypted admin secret to %s", path)
	if err := os.WriteFile(path, encryptedAdminSecret, 0600); err != nil {
		return fmt.Errorf("failed to store token for role %s: %v", adminResult.RoleID, err)
	}

	if err := v.RevokeToken(initResult.RootToken); err != nil {
		return fmt.Errorf("failed to revoke root token: %w", err)
	}

	return nil
}

func main() {
	cfg := config.Config{}

	// TPM flags
	flag.StringVar(&cfg.TPMDevicePath, "tpm.device-path", "/dev/tpmrm0", "The path to the TPM device.")
	flag.UintVar(&cfg.TPMHandle, "tpm.handle", 0x81010001, "The persistent handle for the TPM key.")

	// Vault flags
	flag.StringVar(&cfg.VaultAddress, "vault.address", "http://127.0.0.1:8200", "The address of the Vault server.")
	flag.BoolVar(&cfg.VaultTLSSkipVerify, "vault.tls.skip-verify", false, "If set, skip TLS verification.")
	flag.StringVar(&cfg.VaultTLSCACert, "vault.tls.ca-cert", "", "Path to a CA certificate file for TLS verification.")
	flag.StringVar(&cfg.VaultTLSServerName, "vault.tls.server-name", "", "Server name to use for TLS verification.")

	flag.StringVar(&cfg.StorePath, "store-path", "./keys", "Path to store encrypted keys.")

	// Init flags
	flag.StringVar(&cfg.InitRecoveryPubKey, "init.recovery-public-key", "", "Public key for encrypting recovery keys.")
	flag.StringVar(&cfg.InitAdminRoleID, "init.admin-role-id", "admin", "Role ID for the admin AppRole.")
	flag.StringVar(&cfg.InitAdminPubKey, "init.admin-public-key", "", "Public key for encrypting the admin AppRole secret.")
	flag.IntVar(&cfg.InitKeyShares, "init.key-shares", 5, "Number of unseal keys to generate.")
	flag.IntVar(&cfg.InitKeySharesSaved, "init.key-shares-saved", 3, "Number of unseal keys to save encrypted with TPM.")
	flag.IntVar(&cfg.InitKeyThreshold, "init.key-threshold", 3, "Number of unseal keys required to unseal.")

	flag.Parse()

	if err := run(cfg); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}

// storeKeys encrypts and saves the unseal keys.
func storeKeys(cfg config.Config, keys []string, recoveryPubKey *rsa.PublicKey) error {
	log.Printf("Processing %d unseal keys...", cfg.InitKeyShares)

	// We save the recovery keys first in case some error occurs with the TPM
	for i, key := range keys {
		log.Printf("Encrypting unseal key %d with recovery key...", i)
		encryptedKey, err := crypto.EncryptWithRSA(recoveryPubKey, []byte(key))
		if err != nil {
			return fmt.Errorf("failed to encrypt unseal key %d with recovery key: %v", i, err)
		}
		fileName := fmt.Sprintf("unseal-key-%d.recovery.enc", i)
		path := filepath.Join(cfg.StorePath, fileName)
		if err := os.WriteFile(path, encryptedKey, 0600); err != nil {
			return fmt.Errorf("failed to store recovery-encrypted unseal key %d: %v", i, err)
		}
	}

	tpm, err := crypto.OpenTPM(cfg.TPMDevicePath, uint32(cfg.TPMHandle))
	if err != nil {
		return fmt.Errorf("failed to open TPM: %w", err)
	}
	defer tpm.Close()

	// TPM encryption for specified number of keys
	for i := 0; i < cfg.InitKeySharesSaved; i++ {
		key := keys[i]
		log.Printf("Encrypting unseal key %d with TPM...", i)
		encryptedKey, err := tpm.Encrypt([]byte(key))
		if err != nil {
			return fmt.Errorf("failed to encrypt unseal key %d with TPM: %v", i, err)
		}
		fileName := fmt.Sprintf("unseal-key-%d.tpm.enc", i)
		path := filepath.Join(cfg.StorePath, fileName)

		if err := os.WriteFile(path, encryptedKey, 0600); err != nil {
			return fmt.Errorf("failed to store TPM-encrypted unseal key %d: %v", i, err)
		}
	}

	return nil
}
