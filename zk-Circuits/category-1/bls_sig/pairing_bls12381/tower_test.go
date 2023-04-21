package pairing_bls12381

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type e2Add struct {
	A, B, C E2
}

func (circuit *e2Add) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e2Add{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Sub struct {
	A, B, C E2
}

func (circuit *e2Sub) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e2Sub{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Double struct {
	A, C E2
}

func (circuit *e2Double) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Double(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDoubleFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Double(&a)

	witness := e2Double{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Double{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Mul struct {
	A, B, C E2
}

func (circuit *e2Mul) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e2Mul{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Square struct {
	A, C E2
}

func (circuit *e2Square) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.Square(&a)

	witness := e2Square{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Div struct {
	A, B, C E2
}

func (circuit *e2Div) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Div(&a, &b)

	witness := e2Div{
		A: FromE2(&a),
		B: FromE2(&b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2MulByElement struct {
	A E2
	B baseEl
	C E2 `gnark:",public"`
}

func (circuit *e2MulByElement) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.MulByElement(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulByElement(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	var b fp.Element
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.MulByElement(&a, &b)

	witness := e2MulByElement{
		A: FromE2(&a),
		B: emulated.ValueOf[emulated.BLS12381Fp](b),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2MulByElement{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2MulByNonResidue struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2MulByNonResidue) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp2ByNonResidue(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	witness := e2MulByNonResidue{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2MulByNonResidue{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e2Neg struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2Neg) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Neg(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestNegFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.Neg(&a)

	witness := e2Neg{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Neg{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e2Conjugate struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2Conjugate) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Conjugate(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestConjugateFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness := e2Conjugate{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e2Inverse struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *e2Inverse) Define(api frontend.API) error {
	e := NewExt2(api)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E2
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness := e2Inverse{
		A: FromE2(&a),
		C: FromE2(&c),
	}

	err := test.IsSolved(&e2Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Add struct {
	A, B, C E6
}

func (circuit *e6Add) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e6Add{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Sub struct {
	A, B, C E6
}

func (circuit *e6Sub) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e6Sub{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Mul struct {
	A, B, C E6
}

func (circuit *e6Mul) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e6Mul{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Square struct {
	A, C E6
}

func (circuit *e6Square) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	_, _ = a.SetRandom()
	c.Square(&a)

	witness := e6Square{
		A: FromE6(&a),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Div struct {
	A, B, C E6
}

func (circuit *e6Div) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Div(&a, &b)

	witness := e6Div{
		A: FromE6(&a),
		B: FromE6(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6MulByNonResidue struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *e6MulByNonResidue) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp6ByNonResidue(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	witness := e6MulByNonResidue{
		A: FromE6(&a),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6MulByNonResidue{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6MulByE2 struct {
	A E6
	B E2
	C E6 `gnark:",public"`
}

func (circuit *e6MulByE2) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.MulByE2(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp6ByE2(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	var b bls12381.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.MulByE2(&a, &b)

	witness := e6MulByE2{
		A: FromE6(&a),
		B: FromE2(&b),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6MulByE2{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6MulBy01 struct {
	A      E6
	C0, C1 E2
	C      E6 `gnark:",public"`
}

func (circuit *e6MulBy01) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.MulBy01(&circuit.A, &circuit.C0, &circuit.C1)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestMulFp6By01(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	var C0, C1 bls12381.E2
	_, _ = a.SetRandom()
	_, _ = C0.SetRandom()
	_, _ = C1.SetRandom()
	c.Set(&a)
	c.MulBy01(&C0, &C1)

	witness := e6MulBy01{
		A:  FromE6(&a),
		C0: FromE2(&C0),
		C1: FromE2(&C1),
		C:  FromE6(&c),
	}

	err := test.IsSolved(&e6MulBy01{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e6Neg struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *e6Neg) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Neg(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestNegFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	_, _ = a.SetRandom()
	c.Neg(&a)

	witness := e6Neg{
		A: FromE6(&a),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Neg{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e6Inverse struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *e6Inverse) Define(api frontend.API) error {
	e := NewExt6(api)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp6(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E6
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness := e6Inverse{
		A: FromE6(&a),
		C: FromE6(&c),
	}

	err := test.IsSolved(&e6Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Add struct {
	A, B, C E12
}

func (circuit *e12Add) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e12Add{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Sub struct {
	A, B, C E12
}

func (circuit *e12Sub) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e12Sub{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Mul struct {
	A, B, C E12
}

func (circuit *e12Mul) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e12Mul{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Div struct {
	A, B, C E12
}

func (circuit *e12Div) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.DivUnchecked(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestDivFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c bls12381.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Div(&a, &b)

	witness := e12Div{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Div{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Square struct {
	A, C E12
}

func (circuit *e12Square) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSquareFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E12
	_, _ = a.SetRandom()
	c.Square(&a)

	witness := e12Square{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type e12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Conjugate) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Conjugate(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestConjugateFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E12
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness := e12Conjugate{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12Inverse struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *e12Inverse) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestInverseFp12(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E12
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness := e12Inverse{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12ExptTorus struct {
	A E6
	C E12 `gnark:",public"`
}

func (circuit *e12ExptTorus) Define(api frontend.API) error {
	e := NewExt12(api)
	z := e.ExptTorus(&circuit.A)
	expected := e.DecompressTorus(z)
	e.AssertIsEqual(expected, &circuit.C)

	return nil
}

func TestFp12ExptTorus(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c bls12381.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bls12381.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	c.Expt(&a)
	_a, _ := a.CompressTorus()
	witness := e12ExptTorus{
		A: FromE6(&_a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&e12ExptTorus{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e12MulBy014 struct {
	A    E12 `gnark:",public"`
	W    E12
	B, C E2
}

func (circuit *e12MulBy014) Define(api frontend.API) error {
	e := NewExt12(api)
	res := e.MulBy014(&circuit.A, &circuit.B, &circuit.C)
	e.AssertIsEqual(res, &circuit.W)
	return nil
}

func TestFp12MulBy014(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, w bls12381.E12
	_, _ = a.SetRandom()
	var one, b, c bls12381.E2
	one.SetOne()
	_, _ = b.SetRandom()
	_, _ = c.SetRandom()
	w.Set(&a)
	w.MulBy014(&b, &c, &one)

	witness := e12MulBy014{
		A: FromE12(&a),
		B: FromE2(&b),
		C: FromE2(&c),
		W: FromE12(&w),
	}

	err := test.IsSolved(&e12MulBy014{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

// Torus-based arithmetic
type torusCompress struct {
	A E12
	C E6 `gnark:",public"`
}

func (circuit *torusCompress) Define(api frontend.API) error {
	e := NewExt12(api)
	expected := e.CompressTorus(&circuit.A)
	e.Ext6.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestTorusCompress(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a bls12381.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bls12381.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	c, _ := a.CompressTorus()

	witness := torusCompress{
		A: FromE12(&a),
		C: FromE6(&c),
	}

	err := test.IsSolved(&torusCompress{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type torusDecompress struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *torusDecompress) Define(api frontend.API) error {
	e := NewExt12(api)
	compressed := e.CompressTorus(&circuit.A)
	expected := e.DecompressTorus(compressed)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestTorusDecompress(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a bls12381.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	var tmp bls12381.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	d, _ := a.CompressTorus()
	c := d.DecompressTorus()

	witness := torusDecompress{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&torusDecompress{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type torusMul struct {
	A E12
	B E12
	C E12 `gnark:",public"`
}

func (circuit *torusMul) Define(api frontend.API) error {
	e := NewExt12(api)
	compressedA := e.CompressTorus(&circuit.A)
	compressedB := e.CompressTorus(&circuit.B)
	compressedAB := e.MulTorus(compressedA, compressedB)
	expected := e.DecompressTorus(compressedAB)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestTorusMul(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, b, c, tmp bls12381.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()

	// put a in the cyclotomic subgroup
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)
	// put b in the cyclotomic subgroup
	tmp.Conjugate(&b)
	b.Inverse(&b)
	tmp.Mul(&tmp, &b)
	b.FrobeniusSquare(&tmp).Mul(&b, &tmp)

	// uncompressed mul
	c.Mul(&a, &b)

	witness := torusMul{
		A: FromE12(&a),
		B: FromE12(&b),
		C: FromE12(&c),
	}

	err := test.IsSolved(&torusMul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type torusInverse struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *torusInverse) Define(api frontend.API) error {
	e := NewExt12(api)
	compressed := e.CompressTorus(&circuit.A)
	compressed = e.InverseTorus(compressed)
	expected := e.DecompressTorus(compressed)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestTorusInverse(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c, tmp bls12381.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	// uncompressed inverse
	c.Inverse(&a)

	witness := torusInverse{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&torusInverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type torusFrobenius struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *torusFrobenius) Define(api frontend.API) error {
	e := NewExt12(api)
	compressed := e.CompressTorus(&circuit.A)
	compressed = e.FrobeniusTorus(compressed)
	expected := e.DecompressTorus(compressed)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestTorusFrobenius(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c, tmp bls12381.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	// uncompressed frobenius
	c.Frobenius(&a)

	witness := torusFrobenius{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&torusFrobenius{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type torusFrobeniusSquare struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *torusFrobeniusSquare) Define(api frontend.API) error {
	e := NewExt12(api)
	compressed := e.CompressTorus(&circuit.A)
	compressed = e.FrobeniusSquareTorus(compressed)
	expected := e.DecompressTorus(compressed)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestTorusFrobeniusSquare(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c, tmp bls12381.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	// uncompressed frobeniusSquare
	c.FrobeniusSquare(&a)

	witness := torusFrobeniusSquare{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&torusFrobeniusSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type torusSquare struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *torusSquare) Define(api frontend.API) error {
	e := NewExt12(api)
	compressed := e.CompressTorus(&circuit.A)
	compressed = e.SquareTorus(compressed)
	expected := e.DecompressTorus(compressed)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestTorusSquare(t *testing.T) {

	assert := test.NewAssert(t)
	// witness values
	var a, c, tmp bls12381.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	// uncompressed square
	c.Square(&a)

	witness := torusSquare{
		A: FromE12(&a),
		C: FromE12(&c),
	}

	err := test.IsSolved(&torusSquare{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
