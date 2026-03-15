package config

import (
	"encoding/base64"
	"fmt"

	"github.com/zalando/go-keyring"
)

const keyringService = "com.ackagent.ackagent"

// keyringKey generates a profile-namespaced keyring key
func keyringKey(profileName, keyType, userID string) string {
	return fmt.Sprintf("%s-%s-%s", profileName, keyType, userID)
}

func storePrivateKey(ref string, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return keyring.Set(keyringService, ref, encoded)
}

func loadPrivateKey(ref string) ([]byte, error) {
	encoded, err := keyring.Get(keyringService, ref)
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func deletePrivateKey(ref string) error {
	return keyring.Delete(keyringService, ref)
}

// migrateKeyringKey copies a keyring value from old key to new key, then deletes old
func migrateKeyringKey(oldRef, newRef string) error {
	value, err := keyring.Get(keyringService, oldRef)
	if err != nil {
		return err // Key doesn't exist or can't be read
	}
	if err := keyring.Set(keyringService, newRef, value); err != nil {
		return err
	}
	// Delete old key (ignore errors)
	_ = keyring.Delete(keyringService, oldRef)
	return nil
}
