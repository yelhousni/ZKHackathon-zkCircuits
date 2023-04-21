package pairing_bls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2Affine struct {
	X, Y E2
}

func NewG2Affine(v bls12381.G2Affine) G2Affine {
	return G2Affine{
		X: E2{
			A0: emulated.ValueOf[emulated.BLS12381Fp](v.X.A0),
			A1: emulated.ValueOf[emulated.BLS12381Fp](v.X.A1),
		},
		Y: E2{
			A0: emulated.ValueOf[emulated.BLS12381Fp](v.Y.A0),
			A1: emulated.ValueOf[emulated.BLS12381Fp](v.Y.A1),
		},
	}
}
