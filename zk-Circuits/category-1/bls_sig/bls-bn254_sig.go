package bls_sig

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	bn "github.com/yelhousni/ZKHackathon/zk-Circuits/category-1/bls_sig/pairing_bn254"
)

type BLS struct {
	pr *bn.Pairing
}

func NewBLS(api frontend.API) (*BLS, error) {
	pairing, err := bn.NewPairing(api)
	if err != nil {
		return nil, fmt.Errorf("new pairing: %w", err)
	}
	return &BLS{
		pr: pairing,
	}, nil
}

func (bls BLS) VerifyBLS(pubKey *bn.G1Affine, sig, hash *bn.G2Affine) {
	// canonical generator of the trace-zero r-torsion on BN254
	_, _, g1, _ := bn254.Generators()
	g1.Neg(&g1)
	G1neg := bn.G1Affine{
		X: emulated.ValueOf[emulated.BN254Fp](g1.X),
		Y: emulated.ValueOf[emulated.BN254Fp](g1.Y),
	}

	// e(-G1, σ) * e(pubKey, H(m)) == 1
	bls.pr.PairingCheck([]*bn.G1Affine{&G1neg, pubKey}, []*bn.G2Affine{sig, hash})
}
