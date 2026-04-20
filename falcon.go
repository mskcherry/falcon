package falcon

// NOTE: CGO wrapper for NIST PQC Falcon-1024 (PQClean implementation)
// Thisreplaces the non-standard deterministic variant.

/*
#cgo CFLAGS: -O3 -Wall -Wextra
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "api.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

var (
	ErrKeygenFail = errors.New("falcon keygen failed")
	ErrSignFail   = errors.New("falcon sign failed")
	ErrVerifyFail = errors.New("falcon verify failed")
)

const (
	// PublicKeySize is the size of a Falcon-1024 public key.
	PublicKeySize = int(C.PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES)

	// PrivateKeySize is the size of a Falcon-1024 private key.
	PrivateKeySize = int(C.PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES)

	// SignatureMaxSize is the max size of a Falcon-1024 signature.
	SignatureMaxSize = int(C.PQCLEAN_FALCON1024_CLEAN_CRYPTO_BYTES)
)

// PublicKey represents a falcon public key
type PublicKey [PublicKeySize]byte

// PrivateKey represents a falcon private key
type PrivateKey [PrivateKeySize]byte

// Signature represents a standard Falcon signature (variable length for compressed, max 1462 bytes)
type Signature []byte

// GenerateKey generates a public/private key pair.
// Note: PQClean uses its internal PRNG (or system PRNG via randombytes).
func GenerateKey() (PublicKey, PrivateKey, error) {
	var publicKey PublicKey
	var privateKey PrivateKey

	r := C.PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		(*C.uint8_t)(unsafe.Pointer(&privateKey[0])),
	)

	if r != 0 {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("error code is %d: %w", int(r), ErrKeygenFail)
	}

	return publicKey, privateKey, nil
}

// Sign signs the message with privateKey and returns a signature.
func (sk *PrivateKey) Sign(msg []byte) (Signature, error) {
	var sigLen C.size_t
	var sig [SignatureMaxSize]byte
	var r C.int

	var msgPtr *C.uint8_t
	var msgLen C.size_t
	if len(msg) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
		msgLen = C.size_t(len(msg))
	}

	r = C.PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
		&sigLen,
		msgPtr,
		msgLen,
		(*C.uint8_t)(unsafe.Pointer(&(*sk)[0])),
	)

	if r != 0 {
		return nil, fmt.Errorf("error code %d: %w", int(r), ErrSignFail)
	}

	runtime.KeepAlive(msg)
	runtime.KeepAlive(sk)

	result := make([]byte, int(sigLen))
	copy(result, sig[:sigLen])
	return result, nil
}

// Verify reports whether signature is a valid signature of msg under publicKey.
func (pk *PublicKey) Verify(signature Signature, msg []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("empty signature: %w", ErrVerifyFail)
	}

	var msgPtr *C.uint8_t
	var msgLen C.size_t
	if len(msg) > 0 {
		msgPtr = (*C.uint8_t)(unsafe.Pointer(&msg[0]))
		msgLen = C.size_t(len(msg))
	}

	r := C.PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(
		(*C.uint8_t)(unsafe.Pointer(&signature[0])),
		C.size_t(len(signature)),
		msgPtr,
		msgLen,
		(*C.uint8_t)(unsafe.Pointer(&(*pk)[0])),
	)

	if r != 0 {
		return fmt.Errorf("error code %d: %w", int(r), ErrVerifyFail)
	}

	runtime.KeepAlive(msg)
	runtime.KeepAlive(signature)
	runtime.KeepAlive(pk)
	return nil
}
