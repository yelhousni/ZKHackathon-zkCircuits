package ecdsa

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// Signature represents the signature for some message.
type Signature[Scalar emulated.FieldParams] struct {
	R, S emulated.Element[Scalar]
}

// PublicKey represents the public key to verify the signature for.
type PublicKey[Base, Scalar emulated.FieldParams] AffinePoint[Base]

// Verify asserts that the signature sig verifies for the message msg and public
// key pk. The curve parameters params define the elliptic curve.
//
// We assume that the message msg is already hashed to the scalar field.
func (pk PublicKey[T, S]) Verify(api frontend.API, params CurveParams, msg *emulated.Element[S], sig *Signature[S]) {
	cr, err := New[T, S](api, params)
	if err != nil {
		// TODO: softer handling.
		panic(err)
	}
	scalarApi, err := emulated.NewField[S](api)
	if err != nil {
		panic(err)
	}
	baseApi, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}
	pkpt := AffinePoint[T](pk)
	sInv := scalarApi.Inverse(&sig.S)
	msInv := scalarApi.MulMod(msg, sInv)
	rsInv := scalarApi.MulMod(&sig.R, sInv)

	// q = [rsInv]pkpt + [msInv]g
	q := cr.jointScalarMulBase(&pkpt, rsInv, msInv)
	qx := baseApi.Reduce(&q.X)
	qxBits := baseApi.ToBits(qx)
	rbits := scalarApi.ToBits(&sig.R)
	if len(rbits) != len(qxBits) {
		panic("non-equal lengths")
	}
	for i := range rbits {
		api.AssertIsEqual(rbits[i], qxBits[i])
	}
}
