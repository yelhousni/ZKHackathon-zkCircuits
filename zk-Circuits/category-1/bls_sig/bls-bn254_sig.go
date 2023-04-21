package bls_sig

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	bn "github.com/yelhousni/ZKHackathon/zk-Circuits/category-1/bls_sig/pairing_bn254"
)

type BLS_bn struct {
	pr *bn.Pairing
}

func NewBLS_bn(api frontend.API) (*BLS_bn, error) {
	pairing_bn, err := bn.NewPairing(api)
	if err != nil {
		return nil, fmt.Errorf("new pairing: %w", err)
	}
	return &BLS_bn{
		pr: pairing_bn,
	}, nil
}

// Minimal-pubkey-size variant: public keys are points in G1, signatures are points in G2.
//
// N.B: Implementations using signature aggregation SHOULD use this approach, since
// the size of (PK_1, ..., PK_n, signature) is dominated by the public keys
// even for small n.
// This variant is compatible with Ethereum PoS.
func (bls BLS_bn) VerifyBLS_bn_v1(pubKey *bn.G1Affine, sig, hash *bn.G2Affine) {
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

// Minimal-signature-size variant: signatures are points in G1, public keys are points in G2.
func (bls BLS_bn) VerifyBLS_bn_v2(sig, hash *bn.G1Affine, pubKey *bn.G2Affine) {
	// canonical generator of the trace-zero r-torsion on BN254
	_, _, _, g2 := bn254.Generators()
	g2.Neg(&g2)
	G2neg := bn.G2Affine{
		X: bn.E2{
			A0: emulated.ValueOf[emulated.BN254Fp](g2.X.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](g2.X.A1),
		},
		Y: bn.E2{
			A0: emulated.ValueOf[emulated.BN254Fp](g2.Y.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](g2.Y.A1),
		},
	}

	// e(σ, -G2) * e(H(m), pubKey) == 1
	bls.pr.PairingCheck([]*bn.G1Affine{sig, hash}, []*bn.G2Affine{&G2neg, pubKey})
}
