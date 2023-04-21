package bls_sig

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	bls12 "github.com/yelhousni/ZKHackathon/zk-Circuits/category-1/bls_sig/pairing_bls12381"
)

type blsVerifyCircuit_bls12 struct {
	PK  bls12.G1Affine
	Sig bls12.G2Affine
	HM  bls12.G2Affine
}

func (c *blsVerifyCircuit_bls12) Define(api frontend.API) error {
	bls, err := NewBLS_bls12(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)

	}

	bls.VerifyBLS_bls12(&c.PK, &c.Sig, &c.HM)
	return nil

}

func TestBLS_bls12_Verify_v1(t *testing.T) {
	assert := test.NewAssert(t)
	genPriv := func() *big.Int {
		secret, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(130), nil))
		if err != nil {
			panic(err)

		}
		return secret

	}

	secret := genPriv()

	var PK bls12381.G1Affine
	PK.ScalarMultiplicationBase(secret)

	HM, err := bls12381.HashToG2([]byte("Hello, World!"), []byte("test"))
	if err != nil {
		panic(err)

	}

	var Sig bls12381.G2Affine
	Sig.ScalarMultiplication(&HM, secret)

	witness := &blsVerifyCircuit_bls12{
		PK:  bls12.NewG1Affine(PK),
		Sig: bls12.NewG2Affine(Sig),
		HM:  bls12.NewG2Affine(HM),
	}

	err = test.IsSolved(&blsVerifyCircuit_bls12{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// bench
func BenchmarkBLS2Verify(b *testing.B) {
	var c blsVerifyCircuit_bls12
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("⏱️  BLS signature verifier on BLS12-381 in a BN254 R1CS circuit: ", p.NbConstraints())
}
