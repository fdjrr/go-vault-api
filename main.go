package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"os"

	vault "github.com/hashicorp/vault/api"
)

type KeyPairResponse struct {
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
}

type VaultPathRequest struct {
	Path string `json:"path"`
}

func generateKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VaultPathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "Missing Vault path", http.StatusBadRequest)
		return
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(w, "Failed to generate RSA keys", http.StatusInternalServerError)
		return
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		http.Error(w, "Failed to encode public key", http.StatusInternalServerError)
		return
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	config := vault.DefaultConfig()
	config.Address = vaultAddr

	client, err := vault.NewClient(config)
	if err != nil {
		http.Error(w, "Failed to initialize Vault client", http.StatusInternalServerError)
		return
	}
	client.SetToken(vaultToken)

	_, err = client.Logical().Write(req.Path, map[string]interface{}{
		"data": map[string]interface{}{
			"public_key":  string(pubPEM),
			"private_key": string(privPEM),
		},
	})
	if err != nil {
		http.Error(w, "Failed to store keys in Vault", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(KeyPairResponse{
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
	})
}

func getKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VaultPathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Path == "" {
		http.Error(w, "Missing Vault path", http.StatusBadRequest)
		return
	}

	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")

	config := vault.DefaultConfig()
	config.Address = vaultAddr

	client, err := vault.NewClient(config)
	if err != nil {
		http.Error(w, "Failed to initialize Vault client", http.StatusInternalServerError)
		return
	}
	client.SetToken(vaultToken)

	secret, err := client.Logical().Read(req.Path)
	if err != nil || secret == nil {
		http.Error(w, "Failed to read from Vault", http.StatusInternalServerError)
		return
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		http.Error(w, "Invalid Vault data structure", http.StatusInternalServerError)
		return
	}

	publicKey, _ := data["public_key"].(string)
	privateKey, _ := data["private_key"].(string)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(KeyPairResponse{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	})
}

func main() {
	http.HandleFunc("/generateKey", generateKey)
	http.HandleFunc("/getKey", getKey)

	log.Println("Server running at http://localhost:54625")
	log.Fatal(http.ListenAndServe(":54625", nil))
}
