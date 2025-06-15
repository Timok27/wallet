go-hdwallet – Генерация мнемоники, HD-деривация (BIP-39/-32/-44). 
```go
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
```

Структура BIP-44 выглядит следующим образом: m / 44' / 195' / account' / change / address_index
Разделение ролей происходит через account

API методы для каждой роли: 
```go
// Получить адрес для роли и индекса
func GetAddress(role string, index int) (string, error) {
    var account uint32
    switch role {
        case "trader": account = 0
        case "admin":  account = 1
        case "merch":  account = 2
        default: return "", errors.New("unknown role")
    }
    path := fmt.Sprintf("m/44'/195'/%d'/0/%d", account, index)
    // деривация, преобразование в адрес...
}

// Создать заявку на вывод (мерч)
func CreateWithdrawRequest(merchID string, amount int64, toAddress string) error {
    // сохранить в БД с статусом "created"
}

// Подтвердить и отправить вывод (админ)
func ApproveAndSendWithdraw(requestID string) error {
    // получить данные заявки, деривировать приватный ключ админа
    // сформировать и подписать транзакцию через gotron-sdk
    // отправить в сеть, обновить статус заявки
}

```
