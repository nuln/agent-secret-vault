// Package vault implements a SecretProvider backed by HashiCorp Vault.
package vault

import (
	"context"
	"fmt"
	"os"

	vaultapi "github.com/hashicorp/vault/api"
	agent "github.com/nuln/agent-core"
)

func init() {
	agent.RegisterPluginConfigSpec(agent.PluginConfigSpec{
		PluginName:  "vault",
		PluginType:  "secret",
		Description: "Reads secrets from HashiCorp Vault (KV v2)",
		Fields: []agent.ConfigField{
			{Key: "address", EnvVar: "VAULT_ADDR", Description: "Vault server address", Type: agent.ConfigFieldString, Required: true},
			{Key: "token", EnvVar: "VAULT_TOKEN", Description: "Vault root/service token", Type: agent.ConfigFieldSecret},
			{Key: "mount", EnvVar: "VAULT_MOUNT", Description: "KV mount path", Default: "secret", Type: agent.ConfigFieldString},
		},
	})

	agent.RegisterSecretProvider("vault", func(opts map[string]any) (agent.SecretProvider, error) {
		addr, _ := opts["address"].(string)
		if addr == "" {
			addr = os.Getenv("VAULT_ADDR")
		}
		token, _ := opts["token"].(string)
		if token == "" {
			token = os.Getenv("VAULT_TOKEN")
		}
		mount, _ := opts["mount"].(string)
		if mount == "" {
			mount = os.Getenv("VAULT_MOUNT")
		}
		if mount == "" {
			mount = "secret"
		}
		return New(addr, token, mount)
	})
}

// VaultSecretProvider implements agent.SecretProvider using HashiCorp Vault KV v2.
type VaultSecretProvider struct {
	client *vaultapi.Client
	mount  string
}

// New creates a VaultSecretProvider.
func New(addr, token, mount string) (*VaultSecretProvider, error) {
	cfg := vaultapi.DefaultConfig()
	if addr != "" {
		cfg.Address = addr
	}
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault secret: create client: %w", err)
	}
	if token != "" {
		client.SetToken(token)
	}
	return &VaultSecretProvider{client: client, mount: mount}, nil
}

// Get reads a secret from Vault KV v2. Key format: "path/to/secret#field" or "path/to/secret" (returns first value).
func (p *VaultSecretProvider) Get(ctx context.Context, key string) (string, error) {
	path := key
	field := "value"

	// Support "path#field" notation
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '#' {
			path = key[:i]
			field = key[i+1:]
			break
		}
	}

	secret, err := p.client.KVv2(p.mount).Get(ctx, path)
	if err != nil {
		return "", fmt.Errorf("vault secret: get %q: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("vault secret: %q not found", path)
	}
	val, ok := secret.Data[field]
	if !ok {
		return "", fmt.Errorf("vault secret: field %q not found in %q", field, path)
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("vault secret: field %q in %q is not a string", field, path)
	}
	return str, nil
}
