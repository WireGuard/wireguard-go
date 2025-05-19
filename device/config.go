/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// KeyRotationConfig holds the configuration for key rotation
type KeyRotationConfig struct {
	Enabled      bool
	Interval     time.Duration
	APIEndpoint  string
	APIAuthToken string
}

// DefaultKeyRotationConfig returns the default configuration for key rotation
func DefaultKeyRotationConfig() KeyRotationConfig {
	return KeyRotationConfig{
		Enabled:     false,
		Interval:    24 * time.Hour,
		APIEndpoint: "",
	}
}

// KeyRotationStatus represents the status of the key rotation
type KeyRotationStatus struct {
	LastRotation time.Time
	NextRotation time.Time
}

// StartKeyRotation starts the key rotation process
func (device *Device) StartKeyRotation(config KeyRotationConfig) error {
	if !config.Enabled {
		return nil
	}

	// Start the ticker in a goroutine
	ticker := time.NewTicker(config.Interval)
	go func() {
		for range ticker.C {
			if device.isClosed() {
				ticker.Stop()
				return
			}
			err := device.rotateKeys(config)
			if err != nil {
				device.log.Errorf("Key rotation error: %v", err)
			}
		}
	}()

	device.log.Verbosef("Key rotation started with interval: %s", config.Interval)
	return nil
}

// rotateKeys generates new keys and applies them
func (device *Device) rotateKeys(config KeyRotationConfig) error {
	newPrivateKey := GeneratePrivateKey()
	
	// Set the private key in the device
	err := device.SetPrivateKey(newPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to set private key: %w", err)
	}

	// Get the public key
	publicKey := newPrivateKey.publicKey()
	
	// If an API endpoint is configured, notify it of the key change
	if config.APIEndpoint != "" {
		err = device.notifyKeyChange(config, publicKey)
		if err != nil {
			device.log.Errorf("Failed to notify API of key change: %v", err)
			// Continue anyway, the key has been changed locally
		}
	}
	
	device.log.Verbosef("Keys rotated successfully")
	return nil
}

// notifyKeyChange sends the new public key to the configured API endpoint
func (device *Device) notifyKeyChange(config KeyRotationConfig, publicKey NoisePublicKey) error {
	// Create the request body
	requestBody, err := json.Marshal(map[string]string{
		"public_key": publicKey.String(),
	})
	if err != nil {
		return err
	}
	
	// Create the HTTP request
	req, err := http.NewRequest("POST", config.APIEndpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if config.APIAuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+config.APIAuthToken)
	}
	
	// Send the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	// Check for success
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned non-OK status: %d", resp.StatusCode)
	}
	
	return nil
}

// GeneratePrivateKey generates a new private key
func GeneratePrivateKey() NoisePrivateKey {
	var key NoisePrivateKey
	_, err := rand.Read(key[:])
	if err != nil {
		panic(err)
	}
	
	// Clamp the private key according to the Curve25519
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	
	return key
}

// GetKeyRotationStatus returns the status of the key rotation
func (device *Device) GetKeyRotationStatus(config KeyRotationConfig) KeyRotationStatus {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()
	
	// This is a placeholder implementation
	// In a real implementation, we would track when the keys were last rotated
	now := time.Now()
	return KeyRotationStatus{
		LastRotation: now.Add(-config.Interval),
		NextRotation: now.Add(config.Interval),
	}
} 