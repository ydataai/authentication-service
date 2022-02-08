package services

import (
	"errors"
	"time"

	coreClients "github.com/ydataai/go-core/pkg/common/clients"

	"github.com/google/uuid"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/go-core/pkg/common/logging"
)

type VaultData map[string]interface{}

// ProvisionTokens defines a provision token struct.
type ProvisionTokens struct {
	logger      logging.Logger
	vaultClient *coreClients.VaultClient
}

// NewProvisionTokens defines a ProvisionToken
func NewProvisionTokens(logger logging.Logger, vaultClient *coreClients.VaultClient) ProvisionTokens {
	return ProvisionTokens{
		logger:      logger,
		vaultClient: vaultClient,
	}
}

// Get returns data from the Vault.
func (pt ProvisionTokens) Get(path string) (VaultData, error) {
	return pt.vaultClient.Get(path)
}

// List returns a data list from the Vault.
func (pt ProvisionTokens) List(path string) (interface{}, error) {
	return pt.vaultClient.List(path)
}

// Create stores data into Vault.
func (pt ProvisionTokens) Create(path string, ptr models.ProvisionTokenRequest) (models.CustomClaims, error) {
	if ptr.Name == "" || ptr.Expiration <= 0 {
		return models.CustomClaims{}, errors.New("an error occurred while provisioning the token")
	}

	expirationDay := time.Now().Add(time.Duration(ptr.Expiration) * (time.Hour * 24))
	uuid := uuid.New().String()
	data := VaultData{
		uuid: map[string]interface{}{
			"name":       ptr.Name,
			"expiration": expirationDay.Unix(),
		},
	}
	if err := pt.vaultClient.Patch(path, data); err != nil {
		return models.CustomClaims{}, err
	}

	return models.CustomClaims{
		UID:  uuid,
		Name: ptr.Name,
	}, nil
}

// Update stores updated data into Vault.
func (pt ProvisionTokens) Update(path string, uid string, data interface{}) error {
	newData := VaultData{
		uid: data,
	}
	return pt.vaultClient.Patch(path, newData)
}

// Delete removes a data from the Vault.
func (pt ProvisionTokens) Delete(path string) error {
	return pt.vaultClient.Delete(path)
}
