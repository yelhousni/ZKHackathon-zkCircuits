package bls_sig

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

func (pr Pairing) VerifyBLS(pubKey *G1Affine, sig, hash *G2Affine) {
	// canonical generator of the trace-zero r-torsion on BN254
	_, _, g1, _ := bn254.Generators()
	g1.Neg(&g1)
	G1neg := G1Affine{
		X: emulated.ValueOf[emulated.BN254Fp](g1.X),
		Y: emulated.ValueOf[emulated.BN254Fp](g1.Y),
	}

	// e(-G1, σ) * e(pubKey, H(m)) == 1
	pr.PairingCheck([]*G1Affine{&G1neg, pubKey}, []*G2Affine{sig, hash})
}
