package services

import (
	"fmt"
	"time"

	coreClients "github.com/ydataai/go-core/pkg/common/clients"

	"github.com/google/uuid"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// VaultData stores data from Vault.
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
func (pt ProvisionTokens) Get(path, tokenID string) (VaultData, error) {
	data, err := pt.vaultClient.Get(path)
	if err != nil {
		return nil, err
	}
	// check if the token not exists...
	_, ok := data[tokenID]
	if !ok {
		return nil, fmt.Errorf("%s token not found", tokenID)
	}

	return VaultData{tokenID: data[tokenID]}, nil
}

// List returns a data list from the Vault.
func (pt ProvisionTokens) List(path string) (VaultData, error) {
	return pt.vaultClient.Get(path)
}

// Create stores data into Vault.
func (pt ProvisionTokens) Create(path string, ptr models.ProvisionTokenRequest) (models.CustomClaims, error) {
	expirationDays := time.Now().Add(time.Duration(ptr.Expiration) * (time.Hour * 24))
	tokenID := uuid.New().String()
	data := VaultData{
		tokenID: map[string]interface{}{
			"name":       ptr.Name,
			"expiration": expirationDays.Unix(),
		},
	}
	if err := pt.vaultClient.Patch(path, data); err != nil {
		return models.CustomClaims{}, err
	}

	return models.CustomClaims{
		UUID: tokenID,
		Name: ptr.Name,
	}, nil
}

// Patch stores aditional data into Vault.
func (pt ProvisionTokens) Patch(path string, uuid string, data interface{}) error {
	newData := VaultData{
		uuid: data,
	}
	return pt.vaultClient.Patch(path, newData)
}

// Delete removes a data from the Vault.
func (pt ProvisionTokens) Delete(path, tokenID string) error {
	data, err := pt.List(path)
	if err != nil {
		return err
	}
	pt.logger.Info(data)

	// check if the token not exists...
	_, ok := data[tokenID]
	if !ok {
		return fmt.Errorf("%s token not found", tokenID)
	}
	// ... if exists, delete it.
	delete(data, tokenID)
	err = pt.vaultClient.Delete(path)
	if err != nil {
		return err
	}
	pt.logger.Infof("'%s' token has been deleted.", tokenID)

	for uid, data := range data {
		err = pt.Patch(path, uid, data)
		if err != nil {
			return err
		}
	}

	return nil
}
