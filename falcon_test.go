package falcon

import (
	"crypto/rand"
	mrand "math/rand"
	"testing"
	"time"
)

func TestFalcon(t *testing.T) {
	mrand.Seed(time.Now().Unix())
	for count := 0; count < 64; count++ {
		pub, priv, err := GenerateKey()
		if err != nil {
			t.Fatalf("failed to generate keys. err message: %s", err)
		}

		msg := make([]byte, 500)
		rand.Read(msg)

		sig, err := priv.Sign(msg)
		if err != nil {
			t.Fatalf("failed to sign message. err message: %s", err)
		}

		err = pub.Verify(sig, msg)
		if err != nil {
			t.Fatalf("failed to verify message. err message: %s", err)
		}

		badmsg := make([]byte, len(msg))
		copy(badmsg, msg)
		// Flip a random bit in the message.
		badmsg[mrand.Intn(len(msg))] ^= 1 << mrand.Intn(8)

		err = pub.Verify(sig, badmsg)
		if err == nil {
			t.Fatalf("expected verify to fail on modified message")
		}

		badpub := PublicKey{}
		copy(badpub[:], pub[:])
		badpub[mrand.Intn(len(pub))] ^= 1 << mrand.Intn(8)

		err = badpub.Verify(sig, msg)
		if err == nil {
			t.Fatalf("expected verify to fail with modified public key")
		}
	}
}

func TestFalconSignNilMessage(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	sig, err := priv.Sign(nil)
	if err != nil {
		t.Fatalf("failed to sign message. err message: %s", err)
	}

	err = pub.Verify(sig, nil)
	if err != nil {
		t.Fatalf("failed to verify message. err message: %s", err)
	}

	err = pub.Verify(sig, []byte{})
	if err != nil {
		t.Fatalf("failed to verify message. err message: %s", err)
	}
}

func TestFalconGenerateKeysDifferent(t *testing.T) {
	pub, sk, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	pub2, sk2, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	if pub == pub2 {
		t.Fatalf("public keys are the same")
	}

	if sk == sk2 {
		t.Fatalf("private keys are the same")
	}
}

func TestFalconNilSignature(t *testing.T) {
	pub, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate keys. err message: %s", err)
	}

	msg := make([]byte, 500)
	rand.Read(msg)

	err = pub.Verify(nil, msg)
	if err == nil {
		t.Fatalf("verification succeeded. should have failed.")
	}

	err = pub.Verify([]byte{}, msg)
	if err == nil {
		t.Fatalf("verification succeeded. should have failed.")
	}
}

func BenchmarkFalconKeyGen(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GenerateKey()
	}
}

func BenchmarkFalconSign(b *testing.B) {
	_, sk, err := GenerateKey()
	if err != nil {
		b.Fatalf("GenerateKey with error %v", err)
	}

	strs := make([][64]byte, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.Sign(strs[i][:])
	}
}

func BenchmarkFalconVerify(b *testing.B) {
	pk, sk, err := GenerateKey()
	if err != nil {
		b.Fatalf("GenerateKey with error %v", err)
	}

	strs := make([][64]byte, b.N)
	sigs := make([]Signature, b.N)
	for i := 0; i < b.N; i++ {
		var msg [64]byte
		rand.Read(msg[:])
		strs[i] = msg
		sigs[i], err = sk.Sign(msg[:])
		if err != nil {
			b.Fatalf("Sign failed with error %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pk.Verify(sigs[i], strs[i][:])
	}
}
