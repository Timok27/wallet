package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
)

// Преобразование публичного ключа в TRON-адрес
func publicKeyToTronAddress(pubkey []byte) string {
	ethAddress := crypto.Keccak256(pubkey[1:])[12:]
	tronAddress := append([]byte{0x41}, ethAddress...)
	hash1 := sha256.Sum256(tronAddress)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]
	fullAddress := append(tronAddress, checksum...)
	return base58.Encode(fullAddress)
}

func main() {
	// Генерация мнемоники
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Fatal(err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Mnemonic:", mnemonic)

	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	// Количество подкошельков
	count := 5

	for i := 0; i < count; i++ {
		// Формируем путь деривации для i-го адреса
		derivationPath := fmt.Sprintf("m/44'/195'/0'/0/%d", i)
		path := hdwallet.MustParseDerivationPath(derivationPath)

		account, err := wallet.Derive(path, false)
		if err != nil {
			log.Fatalf("Failed to derive path %s: %v", derivationPath, err)
		}

		privKey, err := wallet.PrivateKey(account)
		if err != nil {
			log.Fatalf("Failed to get private key for path %s: %v", derivationPath, err)
		}

		pubKey := crypto.FromECDSAPub(&privKey.PublicKey)
		tronAddr := publicKeyToTronAddress(pubKey)

		fmt.Printf("\nAddress #%d\n", i)
		fmt.Println("Derivation Path:", derivationPath)
		fmt.Println("TRON Address:", tronAddr)
		fmt.Println("Private Key (hex):", hex.EncodeToString(crypto.FromECDSA(privKey)))
	}
}
