Очередность действий 
1. Создание энтропии (bip39.NewEntropy)
2. Генерация мнемоники (bip39.NewMnemonic)
3. Инициализация HDWallet (hdwallet.NewFromMnemonic)
4. Деривация адресов по ролям (m/44'/195'/x'/0/i)
5. Конвертация pubkey → TRON-адрес
6. Первичное пополнение TRX (FundNewWallet)
7. Проверка баланса, докидывание на комиссии (EnsureFeeCoverage)


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

	"github.com/btcsuite/btcutil/base58"                  // Используется для base58-кодирования TRON-адреса
	"github.com/ethereum/go-ethereum/crypto"              // Генерация ключей и получение публичного ключа
	hdwallet "github.com/miguelmota/go-ethereum-hdwallet" // BIP-32/BIP-44 HD-кошелёк
	"github.com/tyler-smith/go-bip39"                     // Генерация энтропии и мнемоники (BIP-39)
)

// Преобразование публичного ключа (ECDSA) в TRON-адрес (Base58Check)
func publicKeyToTronAddress(pubkey []byte) string {
	// Отрезаем первый байт (0x04), хэшируем Keccak256, берём последние 20 байт
	ethAddress := crypto.Keccak256(pubkey[1:])[12:]

	// Добавляем префикс TRON-сети (0x41 для Mainnet)
	tronAddress := append([]byte{0x41}, ethAddress...)

	// Дважды применяем SHA-256 для вычисления контрольной суммы (checksum)
	hash1 := sha256.Sum256(tronAddress)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]

	// Добавляем контрольную сумму к адресу и кодируем в Base58Check
	fullAddress := append(tronAddress, checksum...)
	return base58.Encode(fullAddress)
}

func main() {
	// Шаг 1: Генерация 256-битной энтропии для создания мнемоники (24 слова)
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Fatal(err)
	}

	// Шаг 2: Генерация мнемонической фразы из энтропии (BIP-39)
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatal(err)
	}

	// Шаг 3: Инициализация HD-кошелька на основе мнемоники (BIP-32)
	wallet, err := hdwallet.NewFromMnemonic(mnemonic)
	if err != nil {
		log.Fatal(err)
	}

	// Количество адресов, которые мы хотим сгенерировать
	count := 5

	for i := 0; i < count; i++ {
		// Шаг 4: Формирование пути деривации (BIP-44: m/44'/195'/0'/0/i)
		// 195 — coin_type для TRON
		// account = 0 (по умолчанию), change = 0 (внешние адреса), index = i
		derivationPath := fmt.Sprintf("m/44'/195'/0'/0/%d", i)
		path := hdwallet.MustParseDerivationPath(derivationPath)

		// Шаг 5: Деривация приватного ключа по пути
		account, err := wallet.Derive(path, false)
		if err != nil {
			log.Fatalf("Failed to derive path %s: %v", derivationPath, err)
		}

		// Получение приватного ключа ECDSA
		privKey, err := wallet.PrivateKey(account)
		if err != nil {
			log.Fatalf("Failed to get private key for path %s: %v", derivationPath, err)
		}

		// Получение публичного ключа и преобразование в TRON-адрес
		pubKey := crypto.FromECDSAPub(&privKey.PublicKey)
		tronAddr := publicKeyToTronAddress(pubKey)

		// Вывод информации
		fmt.Printf("Index %d:\n", i)
		fmt.Println("Derivation Path:", derivationPath)
		fmt.Println("TRON Address:", tronAddr)
		fmt.Println("Private Key:", hex.EncodeToString(crypto.FromECDSA(privKey)))
		fmt.Println()
	}
}

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
// Получение адреса и приватного ключа по роли и индексу
func GetAddressForRole(wallet *hdwallet.Wallet, role string, index int) (string, string, error) {
    var account uint32
    switch role {
    case "trader":
        account = 0
    case "admin":
        account = 1
    case "merch":
        account = 2
    default:
        return "", "", fmt.Errorf("unknown role: %s", role)
    }

    // Формируем путь согласно BIP-44
    derivationPathStr := fmt.Sprintf("m/44'/195'/%d'/0/%d", account, index)
    path := hdwallet.MustParseDerivationPath(derivationPathStr)

    // Деривация
    derivedAccount, err := wallet.Derive(path, false)
    if err != nil {
        return "", "", err
    }

    // Приватный ключ
    privKey, err := wallet.PrivateKey(derivedAccount)
    if err != nil {
        return "", "", err
    }

    // Публичный ключ
    pubKey := crypto.FromECDSAPub(&privKey.PublicKey)

    // Конвертация в TRON-адрес
    tronAddress := publicKeyToTronAddress(pubKey)

    // Приватный ключ в hex
    privKeyHex := hex.EncodeToString(crypto.FromECDSA(privKey))

    return tronAddress, privKeyHex, nil
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

Первичное пополнение кошелька после генерации
```go
func FundNewWallet(targetAddress string, amount int64, masterPrivKey string) error {
	txid, err := SendTRX(masterPrivKey, targetAddress, amount)
	if err != nil {
		return fmt.Errorf("failed to fund wallet: %v", err)
	}
	log.Printf("New wallet funded with %d SUN, txid: %s", amount, txid)
	return nil
}
```

Проверка баланса в SUN (1 TRX = 1 000 000 SUN) 
```go
func GetBalance(address string) (int64, error) {
	account, err := tronClient.GetAccount(address)
	if err != nil {
		return 0, err
	}
	return account.Balance, nil
}
```
TRON использует bandwidth, который начисляется бесплатно каждый день. (~1500 байт)
Одна TRX-транзакция — ~250 байт.
Если адрес превысил лимит bandwidth — TRON списывает TRX с баланса

Проверка остатка bandwidth

```go
func CheckBandwidth(address string) (used int64, limit int64, err error) {
	account, err := tronClient.GetAccount(address)
	if err != nil {
		return 0, 0, err
	}
	return int64(account.FreeNetUsed), int64(account.FreeNetLimit), nil
}
```

Проверяет, есть ли достаточный баланс (TRX) для покрытия комиссий
```go
func EnsureFeeCoverage(addr string, masterPrivKey string) error {
	const MIN_BALANCE = 200_000 // 0.2 TRX как запас

	balance, err := GetBalance(addr)
	if err != nil {
		return err
	}
	if balance >= MIN_BALANCE {
		return nil
	}
}
```

Пополняем с мастер-кошелька
```go
	txid, err := SendTRX(masterPrivKey, addr, MIN_BALANCE)
	if err != nil {
		return fmt.Errorf("failed to fund address for fees: %w", err)
	}
	log.Printf("Address %s funded with TRX for fees, txid: %s", addr, txid)
	return nil
 ```
Перевод TRX
```go
func SendTRX(fromPrivKey, toAddr string, amount int64) (string, error) {
	fromAddr, err := AddressFromPrivKey(fromPrivKey)
	if err != nil {
		return "", err
	}

	// Проверка на покрытие комиссии
	err = EnsureFeeCoverage(fromAddr, MASTER_PRIVATE_KEY)
	if err != nil {
		return "", fmt.Errorf("insufficient TRX for fee: %v", err)
	}

	// Создание и подписание
	tx, err := tronClient.Transfer(fromAddr, toAddr, amount)
	if err != nil {
		return "", err
	}
	signedTx, err := tronClient.SignTransaction(tx, fromPrivKey)
	if err != nil {
		return "", err
	}
	result, err := tronClient.Broadcast(signedTx)
	if err != nil || !result.Result {
		return "", fmt.Errorf("broadcast failed")
	}

	return tx.Txid, nil
}
```
