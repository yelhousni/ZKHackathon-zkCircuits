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
	bn "github.com/yelhousni/ZKHackathon/zk-Circuits/category-1/bls_sig/pairing_bn254"
)

// ----
// v1 (Minimal-pubkey-size variant)
type blsVerifyCircuit_bn_v1 struct {
	PK  bn.G1Affine
	Sig bn.G2Affine
	HM  bn.G2Affine
}

func (c *blsVerifyCircuit_bn_v1) Define(api frontend.API) error {
	bls, err := NewBLS_bn(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)

	}

	bls.VerifyBLS_bn_v1(&c.PK, &c.Sig, &c.HM)
	return nil

}

func TestBLS_bn_Verify_v1(t *testing.T) {
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

	witness := &blsVerifyCircuit_bn_v1{
		PK:  bn.NewG1Affine(PK),
		Sig: bn.NewG2Affine(Sig),
		HM:  bn.NewG2Affine(HM),
	}

	err = test.IsSolved(&blsVerifyCircuit_bn_v1{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// -----
// v2 (Minimal-signature-size variant)
type blsVerifyCircuit_bn_v2 struct {
	Sig bn.G1Affine
	HM  bn.G1Affine
	PK  bn.G2Affine
}

func (c *blsVerifyCircuit_bn_v2) Define(api frontend.API) error {
	bls, err := NewBLS_bn(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)

	}

	bls.VerifyBLS_bn_v2(&c.Sig, &c.HM, &c.PK)
	return nil

}

func TestBLS_bn_Verify_v2(t *testing.T) {
	assert := test.NewAssert(t)
	genPriv := func() *big.Int {
		secret, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(130), nil))
		if err != nil {
			panic(err)

		}
		return secret

	}

	secret := genPriv()

	var PK bn254.G2Affine
	_, _, _, g2 := bn254.Generators()
	PK.ScalarMultiplication(&g2, secret)

	HM, err := bn254.HashToG1([]byte("Hello, World!"), []byte("test"))
	if err != nil {
		panic(err)

	}

	var Sig bn254.G1Affine
	Sig.ScalarMultiplication(&HM, secret)

	witness := &blsVerifyCircuit_bn_v2{
		Sig: bn.NewG1Affine(Sig),
		HM:  bn.NewG1Affine(HM),
		PK:  bn.NewG2Affine(PK),
	}

	err = test.IsSolved(&blsVerifyCircuit_bn_v2{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// bench
func BenchmarkBLSVerify_v1(b *testing.B) {
	var c blsVerifyCircuit_bn_v1
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("⏱️  BLS signature verifier on BN254 in a BN254 R1CS circuit (v1): ", p.NbConstraints())
}

func BenchmarkBLSVerify_v2(b *testing.B) {
	var c blsVerifyCircuit_bn_v2
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	p.Stop()
	fmt.Println("⏱️  BLS signature verifier on BN254 in a BN254 R1CS circuit (v2): ", p.NbConstraints())
}
