// Package passkey is a software stand-in for a platform authenticator (Touch ID, Windows Hello, a security key): a
// P-256 key that produces WebAuthn assertions in the shape browsers return, which LeashAccount verifies on chain
// with OpenZeppelin's WebAuthn library. The eval uses it to co-sign escalations a simulated human approved.
package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// RPID is the relying party the simulated credential is scoped to.
const RPID = "localhost"

const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
)

// Authenticator holds one P-256 credential.
type Authenticator struct {
	key     *ecdsa.PrivateKey
	counter uint32
}

// New generates a fresh credential.
func New() (*Authenticator, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authenticator{key: k}, nil
}

// PublicKey is the credential's (x, y), which the owner registers with setPasskey.
func (a *Authenticator) PublicKey() (x, y [32]byte) {
	b, err := a.key.PublicKey.Bytes() // 0x04 || x || y
	if err != nil {
		panic(err) // a generated P-256 key always encodes
	}
	copy(x[:], b[1:33])
	copy(y[:], b[33:65])
	return x, y
}

// Assertion is a WebAuthn authentication response, field for field OpenZeppelin's WebAuthn.WebAuthnAuth.
type Assertion struct {
	R                 [32]byte
	S                 [32]byte
	ChallengeIndex    *big.Int
	TypeIndex         *big.Int
	AuthenticatorData []byte
	ClientDataJSON    string
}

// Sign produces an assertion over `challenge` (for leash, the user operation hash) with user presence and user
// verification set, as a biometric prompt would.
func (a *Authenticator) Sign(challenge []byte) (*Assertion, error) {
	a.counter++
	rpIDHash := sha256.Sum256([]byte(RPID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flagUserPresent|flagUserVerified)
	authData = binary.BigEndian.AppendUint32(authData, a.counter)

	clientData := fmt.Sprintf(`{"type":"webauthn.get","challenge":"%s","origin":"http://%s","crossOrigin":false}`,
		base64.RawURLEncoding.EncodeToString(challenge), RPID)

	clientHash := sha256.Sum256([]byte(clientData))
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, err
	}
	// On-chain verifiers reject the malleable high-s form.
	n := elliptic.P256().Params().N
	if s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		s = new(big.Int).Sub(n, s)
	}

	as := &Assertion{
		ChallengeIndex:    big.NewInt(int64(strings.Index(clientData, `"challenge":"`))),
		TypeIndex:         big.NewInt(int64(strings.Index(clientData, `"type":"`))),
		AuthenticatorData: authData,
		ClientDataJSON:    clientData,
	}
	r.FillBytes(as.R[:])
	s.FillBytes(as.S[:])
	return as, nil
}

var assertionArgs = func() abi.Arguments {
	t, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "r", Type: "bytes32"},
		{Name: "s", Type: "bytes32"},
		{Name: "challengeIndex", Type: "uint256"},
		{Name: "typeIndex", Type: "uint256"},
		{Name: "authenticatorData", Type: "bytes"},
		{Name: "clientDataJSON", Type: "string"},
	})
	if err != nil {
		panic(err)
	}
	return abi.Arguments{{Type: t}}
}()

// Encode is abi.encode(WebAuthnAuth), the form LeashAccount expects inside a session signature.
func (as *Assertion) Encode() ([]byte, error) {
	return assertionArgs.Pack(*as)
}
