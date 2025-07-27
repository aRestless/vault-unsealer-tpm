# vault-unsealer-tpm

vault-unsealer-tpm is a service to automatically initialize and unseal a HashiCorp Vault using a TPM 2.0 device.

## Preparation
An ideal setup involves up to four separate machines:

- A machine with a TPM 2.0 device that will run the `vault-unsealer-tpm` service.
- A machine with a HashiCorp Vault server that will be initialized and unsealed.
- A secure, ideally air-gapped machine to store the recovery keys.
- A management machine used to decrypt and use the admin AppRole secret created during initialization.

### Create Recovery Key Pair
On the secure recovery machine, create a public key pair that will be used to encrypt the recovery keys:
```sh
openssl genpkey -algorithm RSA -out recovery.private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in recovery.private.pem -out recovery.public.pem
```
Transport the `recovery.public.pem` file to the machine running the `vault-unsealer-tpm` service. This public key will
be used to encrypt the unseal keys during initialization. 

### Create Admin Secret Key Pair
On the management machine, create a public key pair that will be used to encrypt the admin AppRole secret:
```sh
openssl genpkey -algorithm RSA -out admin.private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in admin.private.pem -out admin.public.pem
```
Transport the `admin.public.pem` file to the machine running the `vault-unsealer-tpm` service. This public key will
be used to encrypt the admin AppRole secret during initialization.

## Features

### Initialization
If the given Vault is not initialized, the service will initialize it and store the unseal keys oon disk, by encrypting
them with the TPM. Additionally, the unseal keys will also be encrypted using a given public key so that they can be saved
off-device for recovery purposes.

During initialization, the service will use the root token to create an admin policy and associated AppRole, and encrypt the
AppRole secret with an additional public key. This allows to safely transport the AppRole secret to a management system or
secret store. After this process, the root token will be revoked.

The service will _not_ initialize a Vault if encrypted keys are already present on disk.

**Important Flags**

- `--tpm.handle`: The persistent handle for the TPM key used to encrypt and decrypt the unseal keys. Must be an RSA key
                  and will be created if it does not exist.
- `--vault.address`: The address of the Vault server to be initialized and unsealed.
- `--vault.tls.skip-verify`: If set, the service will not verify the Vault server's TLS certificate during initialization.
                            This can be required if the Vault server is set up with a temporary certificate until it can
                            act as its own CA for TLS certificates.
- `--vault.tls.ca-cert`: The CA certificate to use for verifying the Vault server's TLS certificate. Uses the system's
                         default CA certificates if not set.
- `--init.recovery-public-key`: The public key used to encrypt the unseal keys in addition to the TPM-based encryption.
- `--init.admin-role-id`: The role ID of the AppRole to be created during initialization.
- `--init.admin-public-key`: The public key used to encrypt the AppRole secret.
- `--init.key-shares`: The number of unseal keys to be generated during initialization.
- `--init.key-shares-saved`: The number of unseal keys to be saved on disk using the TPM encryption. Any remaining keys
                             will only be encrypted with the recovery public key.
- `--init.key-threshold`: The number of unseal keys required to unseal the Vault.

### Unsealing
If the given Vault is already initialized, the service will attempt to unseal it by encrypting and using the unseal keys
stored on disk.

## Using the initialized Vault
Transport the encrypted admin AppRole secret (default: `keys/secret-admin.admin.enc`) to the management machine. On this
machine, decrypt the admin AppRole secret using the following `openssl` command:

```sh
openssl pkeyutl -decrypt -inkey admin.private.pem -in secret-admin.admin.enc -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
```
This will output the decrypted AppRole secret, which can then be used to log in to the Vault server using the AppRole's
role ID. Refer to the [Vault documentation](https://developer.hashicorp.com/vault/docs/auth/approle) for details.

## Tests
Please note that the tests currently can only be run with a real TPM device and the associated privileges.