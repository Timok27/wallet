go-hdwallet – Генерация мнемоники, HD-деривация (BIP-39/-32/-44). 

методы:

Создаёт случайную энтропию
```go
func NewEntropy(bits int) ([]byte, error)
```
Создаёт мнемонику на основе сгенерированной энтропии
```go
func NewMnemonic(bits int) (string, error)
```
NewFromMnemonic returns a new wallet from a BIP-39 mnemonic.
```go
func NewFromMnemonic(mnemonic string, passOpt ...string) (*Wallet, error)
```

Пример реализации (добавил функцию преобразования ключа, тк go-hdwallet генерирует адреса для ETH):
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
	}
}
```
для проверки созданных адресов и мненмоники
```go
		fmt.Println("Mnemonic:", mnemonic)
		fmt.Printf("\nAddress #%d\n", i)
		fmt.Println("Derivation Path:", derivationPath)
		fmt.Println("TRON Address:", tronAddr)
		fmt.Println("Private Key (hex):", hex.EncodeToString(crypto.FromECDSA(privKey)))
```
gotron-sdk – Взаимодействие с TRON-сетью: создание и подписание TX. 

Подключение к TRON FullNode
```go
tronClient := client.NewGrpcClient("узел от Tron")
err := tronClient.Start()
if err != nil {
	log.Fatal(err)
}
defer tronClient.Stop()
```
Получение информации о счёте
```go
account, err := tronClient.GetAccount("Tron адрес кошелька")
if err != nil {
	log.Fatal(err)
}
fmt.Println("Balance:", account.Balance) // в SUN 
```
Создание и подписание транзакции (TRX transfer)
```go
// Создание транзакции
tx, err := tronClient.Transfer("адрес отправителя", "адрес получателя", 100_000) // 100_000 SUN = 0.1 TRX
if err != nil {
	log.Fatal(err)
}

// Подпись приватным ключом (hex string)
signedTx, err := tronClient.SignTransaction(tx, "приватный ключ в HEX")
if err != nil {
	log.Fatal(err)
}

// Отправка транзакции
result, err := tronClient.Broadcast(signedTx)
if err != nil {
	log.Fatal(err)
}

fmt.Println("Success:", result.Result)
fmt.Println("TXID:", tx.Txid)

```
Информация о транзакцции
```go
txInfo, err := tronClient.GetTransactionByID("TX_ID_HEX")
if err != nil {
	log.Fatal(err)
}
fmt.Printf("Transaction: %+v\n", txInfo)

```


Структура BIP-44 выглядит следующим образом: 
m/44'/195'/account'/change/address_index
Разделение ролей происходит через account

API методы для каждой роли: 
```go
func GetAddress(role string, index int) (string, error) {
	var account uint32
	switch role {
	case "trader":
		account = 0
	case "admin":
		account = 1
	case "merch":
		account = 2
	default:
		return "", fmt.Errorf("unknown role: %s", role)
	}

	path := fmt.Sprintf("m/44'/195'/%d'/0/%d", account, index)
	derivationPath := hdwallet.MustParseDerivationPath(path)
	accountWallet, err := wallet.Derive(derivationPath, false)
	if err != nil {
		return "", err
	}

	pubKey := crypto.FromECDSAPub(&wallet.PrivateKey(accountWallet).PublicKey)
	return publicKeyToTronAddress(pubKey), nil
}
```
Trader
Использует адреса m/44'/195'/0'/0/i
```go
func GetTraderAddress(index int) (string, error) {
	return GetAddress("trader", index)
}
```
Получить баланс адреса
```go
func GetBalance(address string) (int64, error) {
	account, err := tronClient.GetAccount(address)
	if err != nil {
		return 0, err
	}
	return account.Balance, nil
}
```
Отправить TRX (своим ключом)
```go
func SendTRX(fromPrivKey string, toAddr string, amount int64) (string, error) {
	fromAddr, err := AddressFromPrivKey(fromPrivKey)
	if err != nil {
		return "", err
	}

	tx, err := tronClient.Transfer(fromAddr, toAddr, amount)
	if err != nil {
		return "", err
	}

	signedTx, err := tronClient.SignTransaction(tx, fromPrivKey)
	if err != nil {
		return "", err
	}

	result, err := tronClient.Broadcast(signedTx)
	if err != nil {
		return "", err
	}

	if !result.Result {
		return "", fmt.Errorf("transaction failed")
	}
	return tx.Txid, nil
}
```


Merch
Использует адреса m/44'/195'/2'/0/i

Создать заявку на вывод
```go
func CreateWithdrawRequest(merchID string, index int, toAddress string, amount int64) error {
	// сохранить в БД:
	// merchID, sourceAddress, derivationPath, amount, toAddress, status="created"
	return nil
}
```

Получить адрес для вывода
```go
func GetMerchAddress(index int) (string, error) {
	return GetAddress("merch", index)
}
```

Admin
Использует адреса m/44'/195'/1'/0/i


Утвердить и отправить заявку
```go
func ApproveAndSendWithdraw(requestID string) error {
	// Получить заявку из БД
	req := getWithdrawRequestByID(requestID)
	if req.Status != "created" {
		return fmt.Errorf("invalid status")
	}

	// Получить admin private key (например, index = 0)
	path := hdwallet.MustParseDerivationPath("m/44'/195'/1'/0/0")
	account, err := wallet.Derive(path, false)
	if err != nil {
		return err
	}
	privKey := crypto.FromECDSA(wallet.PrivateKey(account))

	// Создание и отправка транзакции
	tx, err := tronClient.Transfer(req.SourceAddress, req.ToAddress, req.Amount)
	if err != nil {
		return err
	}

	signedTx, err := tronClient.SignTransaction(tx, hex.EncodeToString(privKey))
	if err != nil {
		return err
	}

	result, err := tronClient.Broadcast(signedTx)
	if err != nil || !result.Result {
		return fmt.Errorf("transaction failed or not broadcasted")
	}

	// Обновить статус
	updateRequestStatus(requestID, "sent", tx.Txid)

	return nil
}

```
