package bls_sig

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	bls12 "github.com/yelhousni/ZKHackathon/zk-Circuits/category-1/bls_sig/pairing_bls12381"
)

type BLS_bls12 struct {
	pr *bls12.Pairing
}

func NewBLS_bls12(api frontend.API) (*BLS_bls12, error) {
	pairing_bls12, err := bls12.NewPairing(api)
	if err != nil {
		return nil, fmt.Errorf("new pairing: %w", err)
	}
	return &BLS_bls12{
		pr: pairing_bls12,
	}, nil
}

// Minimal-pubkey-size variant: public keys are points in G1, signatures are points in G2.
//
// N.B: Implementations using signature aggregation SHOULD use this approach, since
// the size of (PK_1, ..., PK_n, signature) is dominated by the public keys
// even for small n.
// This variant is compatible with Ethereum PoS.
func (bls BLS_bls12) VerifyBLS_bls12_v1(pubKey *bls12.G1Affine, sig, hash *bls12.G2Affine) {
	// canonical generator of the trace-zero r-torsion on BLS12-381
	_, _, g1, _ := bls12381.Generators()
	g1.Neg(&g1)
	G1neg := bls12.G1Affine{
		X: emulated.ValueOf[emulated.BLS12381Fp](g1.X),
		Y: emulated.ValueOf[emulated.BLS12381Fp](g1.Y),
	}

	// e(-G1, σ) * e(pubKey, H(m)) == 1
	bls.pr.PairingCheck([]*bls12.G1Affine{&G1neg, pubKey}, []*bls12.G2Affine{sig, hash})
}

// Minimal-signature-size variant: signatures are points in G1, public keys are points in G2.
func (bls BLS_bls12) VerifyBLS_bls12_v2(sig, hash *bls12.G1Affine, pubKey *bls12.G2Affine) {
	pubKey.Y = *bls.pr.Ext2.Neg(&pubKey.Y)

	// e(σ, G2) * e(H(m), -pubKey) == 1
	f, _ := bls.pr.DoublePairFixedQ(hash, sig, pubKey)
	one := bls.pr.Ext12.One()
	bls.pr.Ext12.AssertIsEqual(f, one)
}
