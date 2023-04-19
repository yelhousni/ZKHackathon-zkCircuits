package ecdsa

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark/std/math/emulated"
)

// CurveParams defines parameters of an elliptic curve in short Weierstrass form
// given by the equation
//
//	Y² = X³ + aX + b
//
// The base point is defined by (Gx, Gy).
type CurveParams struct {
	A  *big.Int      // a in curve equation
	B  *big.Int      // b in curve equation
	Gx *big.Int      // base point x
	Gy *big.Int      // base point y
	Gm [][2]*big.Int // m*base point coords
}

// GetSecp256k1Params returns curve parameters for the curve secp256k1. When
// initialising new curve, use the base field [emulated.Secp256k1Fp] and scalar
// field [emulated.Secp256k1Fr].
func GetSecp256k1Params() CurveParams {
	_, g1aff := secp256k1.Generators()
	return CurveParams{
		A:  big.NewInt(0),
		B:  big.NewInt(7),
		Gx: g1aff.X.BigInt(new(big.Int)),
		Gy: g1aff.Y.BigInt(new(big.Int)),
		Gm: computeSecp256k1Table(),
	}
}

// GetCurveParams returns suitable curve parameters given the parametric type Base as base field.
func GetCurveParams[Base emulated.FieldParams]() CurveParams {
	var t Base
	switch t.Modulus().Text(16) {
	case "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f":
		return secp256k1Params
	default:
		panic("no stored parameters")
	}
}

var secp256k1Params CurveParams

func init() {
	secp256k1Params = GetSecp256k1Params()
}
