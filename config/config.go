package config

// Config holds the application's configuration, populated from command-line flags.
type Config struct {
	StorePath string

	// TPM settings
	TPMDevicePath string
	TPMHandle     uint

	// Vault settings
	VaultAddress       string
	VaultTLSSkipVerify bool
	VaultTLSCACert     string
	VaultTLSServerName string

	// Initialization settings
	InitRecoveryPubKey string
	InitAdminRoleID    string
	InitAdminPubKey    string
	InitKeyShares      int
	InitKeySharesSaved int
	InitKeyThreshold   int
}
