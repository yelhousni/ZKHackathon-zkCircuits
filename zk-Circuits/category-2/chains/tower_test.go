package two_chains

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e2Add struct {
	A, B, C E2
}

func (circuit *e2Add) Define(api frontend.API) error {
	var expected E2
	expected.Add(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	var witness e2Add
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Add{}, &witness, test.WithCurves(ecc.BW6_761))

}

type e2Sub struct {
	A, B, C E2
}

func (circuit *e2Sub) Define(api frontend.API) error {
	var expected E2
	expected.Sub(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSubFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	var witness e2Sub
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Sub{}, &witness, test.WithCurves(ecc.BW6_761))

}

type e2Mul struct {
	A, B, C E2
}

func (circuit *e2Mul) Define(api frontend.API) error {
	var expected E2

	expected.Mul(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	var witness e2Mul
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Mul{}, &witness, test.WithCurves(ecc.BW6_761))

}

type e2Div struct {
	A, B, C E2
}

func (circuit *e2Div) Define(api frontend.API) error {
	var expected E2

	expected.DivUnchecked(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDivFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b).Mul(&c, &a)

	var witness e2Div
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Div{}, &witness, test.WithCurves(ecc.BW6_761))

}

type fp2MulByFp struct {
	A E2
	B frontend.Variable
	C E2 `gnark:",public"`
}

func (circuit *fp2MulByFp) Define(api frontend.API) error {
	expected := E2{}
	expected.MulByFp(api, circuit.A, circuit.B)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulByFpFp2(t *testing.T) {

	var circuit, witness fp2MulByFp

	// witness values
	var a, c bls12377.E2
	var b fp.Element
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.MulByElement(&a, &b)

	witness.A.Assign(&a)
	witness.B = (fr.Element)(b)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp2Conjugate struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Conjugate) Define(api frontend.API) error {
	expected := E2{}
	expected.Conjugate(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestConjugateFp2(t *testing.T) {

	var circuit, witness fp2Conjugate

	// witness values
	var a, c bls12377.E2
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp2Inverse struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Inverse) Define(api frontend.API) error {

	expected := E2{}
	expected.Inverse(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestInverseFp2(t *testing.T) {

	var circuit, witness fp2Inverse

	// witness values
	var a, c bls12377.E2
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp6Add struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Add) Define(api frontend.API) error {
	expected := E6{}
	expected.Add(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {

	var circuit, witness fp6Add

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp6Sub struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Sub) Define(api frontend.API) error {
	expected := E6{}
	expected.Sub(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {

	var circuit, witness fp6Sub

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp6Mul struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Mul) Define(api frontend.API) error {
	expected := E6{}

	expected.Mul(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {

	var circuit, witness fp6Mul

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp6MulByNonResidue struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *fp6MulByNonResidue) Define(api frontend.API) error {
	expected := E6{}

	expected.MulByNonResidue(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulByNonResidueFp6(t *testing.T) {

	var circuit, witness fp6MulByNonResidue

	// witness values
	var a, c bls12377.E6
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp6Inverse struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *fp6Inverse) Define(api frontend.API) error {
	expected := E6{}

	expected.Inverse(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestInverseFp6(t *testing.T) {

	var circuit, witness fp6Inverse

	// witness values
	var a, c bls12377.E6
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type e6Div struct {
	A, B, C E6
}

func (circuit *e6Div) Define(api frontend.API) error {
	var expected E6

	expected.DivUnchecked(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDivFp6(t *testing.T) {

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b).Mul(&c, &a)

	var witness e6Div
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e6Div{}, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Add struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Add) Define(api frontend.API) error {
	expected := E12{}
	expected.Add(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddFp12(t *testing.T) {

	var circuit, witness fp12Add

	// witness values
	var a, b, c bls12377.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Sub struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Sub) Define(api frontend.API) error {
	expected := E12{}
	expected.Sub(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSubFp12(t *testing.T) {

	var circuit, witness fp12Sub

	// witness values
	var a, b, c bls12377.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Mul struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Mul) Define(api frontend.API) error {
	expected := E12{}

	expected.Mul(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulFp12(t *testing.T) {

	var circuit, witness fp12Mul

	// witness values
	var a, b, c bls12377.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Square struct {
	A E12
	B E12 `gnark:",public"`
}

func (circuit *fp12Square) Define(api frontend.API) error {

	s := circuit.A.Square(api, circuit.A)
	s.AssertIsEqual(api, circuit.B)
	return nil
}

func TestSquareFp12(t *testing.T) {

	var circuit, witness fp12Square

	// witness values
	var a, b bls12377.E12
	_, _ = a.SetRandom()
	b.Square(&a)

	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp12CycloSquare struct {
	A E12
	B E12 `gnark:",public"`
}

func (circuit *fp12CycloSquare) Define(api frontend.API) error {

	var u, v E12
	u.Square(api, circuit.A)
	v.CyclotomicSquare(api, circuit.A)
	u.AssertIsEqual(api, v)
	u.AssertIsEqual(api, circuit.B)
	return nil
}

func TestFp12CyclotomicSquare(t *testing.T) {

	var circuit, witness fp12CycloSquare

	// witness values
	var a, b bls12377.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup (we assume the group is Fp12, field of definition of bls277)
	var tmp bls12377.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	b.CyclotomicSquare(&a)
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp12CycloSquareCompressed struct {
	A E12
	B E12 `gnark:",public"`
}

func (circuit *fp12CycloSquareCompressed) Define(api frontend.API) error {

	var u, v E12
	u.Square(api, circuit.A)
	v.CyclotomicSquareCompressed(api, circuit.A)
	v.Decompress(api, v)
	u.AssertIsEqual(api, v)
	u.AssertIsEqual(api, circuit.B)
	return nil
}

func TestFp12CyclotomicSquareCompressed(t *testing.T) {

	var circuit, witness fp12CycloSquareCompressed

	// witness values
	var a, b bls12377.E12
	_, _ = a.SetRandom()

	// put a in the cyclotomic subgroup (we assume the group is Fp12, field of definition of bls277)
	var tmp bls12377.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	b.CyclotomicSquareCompressed(&a)
	b.DecompressKarabina(&b)
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12Conjugate) Define(api frontend.API) error {
	expected := E12{}
	expected.Conjugate(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestConjugateFp12(t *testing.T) {

	var circuit, witness fp12Conjugate

	// witness values
	var a, c bls12377.E12
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Frobenius struct {
	A       E12
	C, D, E E12 `gnark:",public"`
}

func (circuit *fp12Frobenius) Define(api frontend.API) error {

	fb := E12{}
	fb.Frobenius(api, circuit.A)
	fb.AssertIsEqual(api, circuit.C)

	fbSquare := E12{}
	fbSquare.FrobeniusSquare(api, circuit.A)
	fbSquare.AssertIsEqual(api, circuit.D)

	return nil
}

func TestFrobeniusFp12(t *testing.T) {

	var circuit, witness fp12Frobenius

	// witness values
	var a, c, d, e bls12377.E12
	_, _ = a.SetRandom()
	c.Frobenius(&a)
	d.FrobeniusSquare(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)
	witness.D.Assign(&d)
	witness.E.Assign(&e)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Inverse struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12Inverse) Define(api frontend.API) error {
	expected := E12{}

	expected.Inverse(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestInverseFp12(t *testing.T) {

	var circuit, witness fp12Inverse

	// witness values
	var a, c bls12377.E12
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type e12Div struct {
	A, B, C E12
}

func (circuit *e12Div) Define(api frontend.API) error {
	var expected E12

	expected.DivUnchecked(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDivFp12(t *testing.T) {

	// witness values
	var a, b, c bls12377.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b).Mul(&c, &a)

	var witness e12Div
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e12Div{}, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12FixedExpo struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12FixedExpo) Define(api frontend.API) error {
	expected := E12{}

	expo := uint64(9586122913090633729)
	expected.Expt(api, circuit.A, expo)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestExpFixedExpoFp12(t *testing.T) {
	var circuit, witness fp12FixedExpo

	// witness values
	var a, b, c bls12377.E12
	expo := uint64(9586122913090633729)

	// put a in the cyclotomic subgroup (we assume the group is Fp12, field of definition of bls277)
	_, _ = a.SetRandom()
	b.Conjugate(&a)
	a.Inverse(&a)
	b.Mul(&b, &a)
	a.FrobeniusSquare(&b).Mul(&a, &b)

	c.Exp(a, new(big.Int).SetUint64(expo))

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12MulBy034 struct {
	A    E12 `gnark:",public"`
	W    E12
	B, C E2
}

func (circuit *fp12MulBy034) Define(api frontend.API) error {

	circuit.A.MulBy034(api, circuit.B, circuit.C)
	circuit.A.AssertIsEqual(api, circuit.W)
	return nil
}

func TestFp12MulBy034(t *testing.T) {

	var circuit, witness fp12MulBy034

	var a bls12377.E12
	var b, c, one bls12377.E2
	one.SetOne()
	_, _ = a.SetRandom()
	witness.A.Assign(&a)

	_, _ = b.SetRandom()
	witness.B.Assign(&b)

	_, _ = c.SetRandom()
	witness.C.Assign(&c)

	a.MulBy034(&one, &b, &c)

	witness.W.Assign(&a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}
