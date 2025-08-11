package doorman

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type bearerSignKey struct {
	publicKey crypto.PublicKey

	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA
	X5t string   `json:"x5t"`
	X5c []string `json:"x5c"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	// EC
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

type JwksUrlResponse struct {
	Keys []bearerSignKey `json:"keys"`
}

type BearerKeyManager struct {
	name             string
	keysUrl          string
	ticker           *time.Ticker
	keys             []*bearerSignKey
	tokenKeysMap     map[string]int
	tokenKeysMapLock sync.RWMutex
}

var idOrder = []string{"kid", "x5t"}

func NewBearerKeyManager(name string, keysUrl string, interval time.Duration) (*BearerKeyManager, error) {
	bkm := &BearerKeyManager{
		name:         name,
		keysUrl:      keysUrl,
		tokenKeysMap: make(map[string]int),
	}

	if interval < time.Minute*5 {
		interval = time.Minute * 5
	}

	if err := bkm.fetchKeys(); err != nil {
		return nil, err
	}

	bkm.ticker = time.NewTicker(interval)

	// background jobs
	go func() {
		for {
			select {
			case <-bkm.ticker.C:
				if err := bkm.fetchKeys(); err != nil {
					logger.Error("Failed to fetch keys: ", "error", err.Error())
				}
			}
		}
	}()

	return bkm, nil
}

// fetchKeys fetches keys from JwksURI
func (bkm *BearerKeyManager) fetchKeys() (err error) {
	var (
		httpClient = &http.Client{Timeout: time.Second * 15}
		request    *http.Request
		response   *http.Response
	)

	logger.Info("Fetching new keys from server", "name", bkm.name, "url", bkm.keysUrl, "timeout", httpClient.Timeout.String())

	if request, err = http.NewRequest("GET", bkm.keysUrl, nil); err != nil {
		return err
	}
	if response, err = httpClient.Do(request); err != nil {
		return err
	}
	if response.Body != nil {
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(response.Body)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("error: %s", response.Status)
	}

	var newKeys *JwksUrlResponse
	if err = json.NewDecoder(response.Body).Decode(&newKeys); err != nil {
		return err
	}

	// create map
	bkm.tokenKeysMapLock.Lock()
	defer bkm.tokenKeysMapLock.Unlock()

	bkm.tokenKeysMap = make(map[string]int)
	bkm.keys = make([]*bearerSignKey, len(newKeys.Keys))
	for idx, key := range newKeys.Keys {
		_key := key
		_key.parsePublicKey()
		bkm.tokenKeysMap[_key.getID()] = idx
		bkm.keys[idx] = &_key
	}

	if len(bkm.keys) == 0 {
		return fmt.Errorf("no keys found")
	}

	return nil
}

// getTokenId returns ID from token header. see idOrder("kid", "x5t")
func (bkm *BearerKeyManager) getTokenId(tokenHeader map[string]any) (tokenId string, err error) {
	var (
		iTokenId any
		found    bool
		castOk   bool
	)

	for _, idVal := range idOrder {
		if iTokenId, found = tokenHeader[idVal]; found {
			break
		}
	}
	if !found {
		return "", fmt.Errorf("no valid token id found in header")
	}

	if tokenId, castOk = iTokenId.(string); !castOk {
		return "", fmt.Errorf("could not parse '%v' to string as token id", iTokenId)
	}

	return tokenId, nil
}

// getSignatureKey returns public key to validate token signature
func (bkm *BearerKeyManager) getSignatureKey(token *jwt.Token) (out any, err error) {
	var (
		ok      bool
		tokenId string
		idx     int
	)

	if tokenId, err = bkm.getTokenId(token.Header); err != nil {
		return nil, fmt.Errorf("could not find valid token id in token header. %s", err)
	}

	bkm.tokenKeysMapLock.RLock()
	defer bkm.tokenKeysMapLock.RUnlock()

	if idx, ok = bkm.tokenKeysMap[tokenId]; !ok {
		return nil, fmt.Errorf("could not find tokenId '%s' in local key cache. keys in cache: %d", tokenId, len(bkm.tokenKeysMap))
	}

	return bkm.keys[idx].publicKey, nil
}

func (bsk *bearerSignKey) parsePublicKey() {
	switch {
	case bsk.Kty == "RSA":
		bsk.publicKey = getRSAPublicKeyFromModulusAndExponent(bsk.N, bsk.E)
	case bsk.Kty == "EC" && bsk.Alg == "ES256":
		bsk.publicKey = getECDSAPublicKeyFromXAndY(elliptic.P256(), bsk.X, bsk.Y)
	case bsk.Kty == "EC" && bsk.Alg == "ES384":
		bsk.publicKey = getECDSAPublicKeyFromXAndY(elliptic.P384(), bsk.X, bsk.Y)
	case bsk.Kty == "EC" && bsk.Alg == "ES512":
		bsk.publicKey = getECDSAPublicKeyFromXAndY(elliptic.P521(), bsk.X, bsk.Y)
		//case "EDDSA":
		//	bsk.publicKey = getED25519PublicKeyFromXAndY()
	default:
		logger.Info("unsupported key", "type", bsk.Kty, "alg", bsk.Alg)
	}

}

// getRSAPublicKeyFromModulusAndExponent gets public key from Modules and Exponent provided from JwksURI
func getRSAPublicKeyFromModulusAndExponent(n, e string) *rsa.PublicKey {
	nBytes, _ := base64.RawURLEncoding.DecodeString(n)
	eBytes, _ := base64.RawURLEncoding.DecodeString(e)

	nBigInt := new(big.Int).SetBytes(nBytes)

	//decoding key.E returns a three byte slice, https://golang.org/pkg/encoding/binary/#Read and other conversions fail
	//since they are expecting to read as many bytes as the size of int being returned (4 bytes for uint32 for example)
	var buffer bytes.Buffer
	buffer.WriteByte(0)
	buffer.Write(eBytes)
	exponent := binary.BigEndian.Uint32(buffer.Bytes())

	return &rsa.PublicKey{N: nBigInt, E: int(exponent)}
}

func getECDSAPublicKeyFromXAndY(curve elliptic.Curve, x, y string) *ecdsa.PublicKey {
	xBytes, _ := base64.RawURLEncoding.DecodeString(x)
	yBytes, _ := base64.RawURLEncoding.DecodeString(y)

	xBigInt := new(big.Int).SetBytes(xBytes)
	yBigInt := new(big.Int).SetBytes(yBytes)

	return &ecdsa.PublicKey{Curve: curve, X: xBigInt, Y: yBigInt}
}

//func getED25519PublicKeyFromXAndY(curve ecdh.Curve, x, y string) *ed25519.PublicKey {
//	xBytes, _ := base64.RawURLEncoding.DecodeString(x)
//	yBytes, _ := base64.RawURLEncoding.DecodeString(y)
//
//	xBigInt := new(big.Int).SetBytes(xBytes)
//	yBigInt := new(big.Int).SetBytes(yBytes)
//
//	return &ed25519.PublicKey{}
//}

func (bsk *bearerSignKey) getID() string {
	for _, idVal := range idOrder {
		switch {
		case idVal == "kid":
			return bsk.Kid
		}
	}
	return bsk.X5t
}
