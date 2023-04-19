package bls_sig

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
)

type blsVerifyCircuit struct {
	PK  G1Affine
	Sig G2Affine
	HM  G2Affine
}

func (c *blsVerifyCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)

	}

	pairing.VerifyBLS(&c.PK, &c.Sig, &c.HM)
	return nil

}

func TestBLSVerifyTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	genPriv := func() *big.Int {
		secret, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(130), nil))
		if err != nil {
			panic(err)

		}
		return secret

	}

	secret := genPriv()

	var PK bn254.G1Affine
	PK.ScalarMultiplicationBase(secret)

	HM, err := bn254.HashToG2([]byte("Hello, World!"), []byte("test"))
	if err != nil {
		panic(err)

	}

	var Sig bn254.G2Affine
	Sig.ScalarMultiplication(&HM, secret)

	witness := &blsVerifyCircuit{
		PK:  NewG1Affine(PK),
		Sig: NewG2Affine(Sig),
		HM:  NewG2Affine(HM),
	}

	err = test.IsSolved(&blsVerifyCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// bench
func BenchmarkBLSVerify(b *testing.B) {
	var c blsVerifyCircuit
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("⏱️  BLS signature verifier on BN254 in a BN254 R1CS circuit: ", p.NbConstraints())
}
