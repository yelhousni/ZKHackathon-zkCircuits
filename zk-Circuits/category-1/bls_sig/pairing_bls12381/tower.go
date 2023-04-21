package pairing_bls12381

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type curveF = emulated.Field[emulated.BLS12381Fp]
type baseEl = emulated.Element[emulated.BLS12381Fp]

type E2 struct {
	A0, A1 baseEl
}

type Ext2 struct {
	api         frontend.API
	fp          *curveF
	nonResidues map[int]map[int]*E2
}

func NewExt2(api frontend.API) *Ext2 {
	fp, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		panic(err)
	}
	pwrs := map[int]map[int]struct {
		A0 string
		A1 string
	}{
		1: {
			1: {"3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760", "151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027"},
			2: {"0", "4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436"},
			3: {"1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257", "1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"},
			4: {"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437", "0"},
			5: {"877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230", "3125332594171059424908108096204648978570118281977575435832422631601824034463382777937621250592425535493320683825557"},
		},
		2: {
			1: {"793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620351", "0"},
			2: {"793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350", "0"},
			3: {"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559786", "0"},
			4: {"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436", "0"},
			5: {"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437", "0"},
		},
	}
	nonResidues := make(map[int]map[int]*E2)
	for pwr, v := range pwrs {
		for coeff, v := range v {
			el := E2{emulated.ValueOf[emulated.BLS12381Fp](v.A0), emulated.ValueOf[emulated.BLS12381Fp](v.A1)}
			if nonResidues[pwr] == nil {
				nonResidues[pwr] = make(map[int]*E2)
			}
			nonResidues[pwr][coeff] = &el
		}
	}
	return &Ext2{api: api, fp: fp, nonResidues: nonResidues}
}

func (e Ext2) MulByElement(x *E2, y *baseEl) *E2 {
	z0 := e.fp.MulMod(&x.A0, y)
	z1 := e.fp.MulMod(&x.A1, y)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) MulByConstElement(x *E2, y *big.Int) *E2 {
	z0 := e.fp.MulConst(&x.A0, y)
	z1 := e.fp.MulConst(&x.A1, y)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Conjugate(x *E2) *E2 {
	z0 := x.A0
	z1 := e.fp.Neg(&x.A1)
	return &E2{
		A0: z0,
		A1: *z1,
	}
}

func (e Ext2) MulByNonResidueGeneric(x *E2, power, coef int) *E2 {
	y := e.nonResidues[power][coef]
	z := e.Mul(x, y)
	return z
}

// MulByNonResidue returns x*(1+u)
func (e Ext2) MulByNonResidue(x *E2) *E2 {
	a := e.fp.Sub(&x.A0, &x.A1)
	b := e.fp.Add(&x.A0, &x.A1)

	return &E2{
		A0: *a,
		A1: *b,
	}
}

// MulByNonResidue1Power1 returns x*(1+u)^(1*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power1(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 1)
}

// MulByNonResidue1Power2 returns x*(1+u)^(2*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power2(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	a := e.fp.MulMod(&x.A1, &element)
	a = e.fp.Neg(a)
	b := e.fp.MulMod(&x.A0, &element)
	return &E2{
		A0: *a,
		A1: *b,
	}
}

// MulByNonResidue1Power3 returns x*(1+u)^(3*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power3(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 3)
}

// MulByNonResidue1Power4 returns x*(1+u)^(4*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power4(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue1Power5 returns x*(1+u)^(5*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power5(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 5)
}

// MulByNonResidue2Power1 returns x*(1+u)^(1*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power1(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BLS12381Fp]("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620351")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue2Power2 returns x*(1+u)^(2*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power2(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BLS12381Fp]("793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue2Power3 returns x*(1+u)^(3*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power3(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559786")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue2Power4 returns x*(1+u)^(4*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power4(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue2Power5 returns x*(1+u)^(5*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power5(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

func (e Ext2) Mul(x, y *E2) *E2 {
	a := e.fp.Add(&x.A0, &x.A1)
	b := e.fp.Add(&y.A0, &y.A1)
	a = e.fp.MulMod(a, b)
	b = e.fp.MulMod(&x.A0, &y.A0)
	c := e.fp.MulMod(&x.A1, &y.A1)
	z1 := e.fp.Sub(a, b)
	z1 = e.fp.Sub(z1, c)
	z0 := e.fp.Sub(b, c)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Add(x, y *E2) *E2 {
	z0 := e.fp.Add(&x.A0, &y.A0)
	z1 := e.fp.Add(&x.A1, &y.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Sub(x, y *E2) *E2 {
	z0 := e.fp.Sub(&x.A0, &y.A0)
	z1 := e.fp.Sub(&x.A1, &y.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Neg(x *E2) *E2 {
	z0 := e.fp.Neg(&x.A0)
	z1 := e.fp.Neg(&x.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) One() *E2 {
	z0 := e.fp.One()
	z1 := e.fp.Zero()
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) Zero() *E2 {
	z0 := e.fp.Zero()
	z1 := e.fp.Zero()
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}
func (e Ext2) IsZero(z *E2) frontend.Variable {
	a0 := e.fp.IsZero(&z.A0)
	a1 := e.fp.IsZero(&z.A1)
	return e.api.And(a0, a1)
}

// returns 1+u
func (e Ext2) NonResidue() *E2 {
	one := e.fp.One()
	return &E2{
		A0: *one,
		A1: *one,
	}
}

func (e Ext2) Square(x *E2) *E2 {
	a := e.fp.Add(&x.A0, &x.A1)
	b := e.fp.Sub(&x.A0, &x.A1)
	a = e.fp.MulMod(a, b)
	b = e.fp.MulMod(&x.A0, &x.A1)
	b = e.fp.MulConst(b, big.NewInt(2))
	return &E2{
		A0: *a,
		A1: *b,
	}
}

func (e Ext2) Double(x *E2) *E2 {
	two := big.NewInt(2)
	z0 := e.fp.MulConst(&x.A0, two)
	z1 := e.fp.MulConst(&x.A1, two)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e Ext2) AssertIsEqual(x, y *E2) {
	e.fp.AssertIsEqual(&x.A0, &y.A0)
	e.fp.AssertIsEqual(&x.A1, &y.A1)
}

func FromE2(y *bls12381.E2) E2 {
	return E2{
		A0: emulated.ValueOf[emulated.BLS12381Fp](y.A0),
		A1: emulated.ValueOf[emulated.BLS12381Fp](y.A1),
	}
}

func (e Ext2) Inverse(x *E2) *E2 {
	res, err := e.fp.NewHint(inverseE2Hint, 2, &x.A0, &x.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	inv := E2{
		A0: *res[0],
		A1: *res[1],
	}
	one := e.One()

	// 1 == inv * x
	_one := e.Mul(&inv, x)
	e.AssertIsEqual(one, _one)

	return &inv

}

func (e Ext2) DivUnchecked(x, y *E2) *E2 {
	res, err := e.fp.NewHint(divE2Hint, 2, &x.A0, &x.A1, &y.A0, &y.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	div := E2{
		A0: *res[0],
		A1: *res[1],
	}

	// x == div * y
	_x := e.Mul(&div, y)
	e.AssertIsEqual(x, _x)

	return &div
}

func (e Ext2) Select(selector frontend.Variable, z1, z0 *E2) *E2 {
	a0 := e.fp.Select(selector, &z1.A0, &z0.A0)
	a1 := e.fp.Select(selector, &z1.A1, &z0.A1)
	return &E2{A0: *a0, A1: *a1}
}

func (e Ext2) Lookup2(s1, s2 frontend.Variable, a, b, c, d *E2) *E2 {
	a0 := e.fp.Lookup2(s1, s2, &a.A0, &b.A0, &c.A0, &d.A0)
	a1 := e.fp.Lookup2(s1, s2, &a.A1, &b.A1, &c.A1, &d.A1)
	return &E2{A0: *a0, A1: *a1}
}

type E6 struct {
	B0, B1, B2 E2
}

type Ext6 struct {
	*Ext2
}

func NewExt6(api frontend.API) *Ext6 {
	return &Ext6{Ext2: NewExt2(api)}
}

func (e Ext6) One() *E6 {
	z0 := e.Ext2.One()
	z1 := e.Ext2.Zero()
	z2 := e.Ext2.Zero()
	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Zero() *E6 {
	z0 := e.Ext2.Zero()
	z1 := e.Ext2.Zero()
	z2 := e.Ext2.Zero()
	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) IsZero(z *E6) frontend.Variable {
	b0 := e.Ext2.IsZero(&z.B0)
	b1 := e.Ext2.IsZero(&z.B1)
	b2 := e.Ext2.IsZero(&z.B2)
	return e.api.And(e.api.And(b0, b1), b2)
}

func (e Ext6) Add(x, y *E6) *E6 {
	z0 := e.Ext2.Add(&x.B0, &y.B0)
	z1 := e.Ext2.Add(&x.B1, &y.B1)
	z2 := e.Ext2.Add(&x.B2, &y.B2)
	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Neg(x *E6) *E6 {
	z0 := e.Ext2.Neg(&x.B0)
	z1 := e.Ext2.Neg(&x.B1)
	z2 := e.Ext2.Neg(&x.B2)
	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Sub(x, y *E6) *E6 {
	z0 := e.Ext2.Sub(&x.B0, &y.B0)
	z1 := e.Ext2.Sub(&x.B1, &y.B1)
	z2 := e.Ext2.Sub(&x.B2, &y.B2)
	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Mul(x, y *E6) *E6 {
	t0 := e.Ext2.Mul(&x.B0, &y.B0)
	t1 := e.Ext2.Mul(&x.B1, &y.B1)
	t2 := e.Ext2.Mul(&x.B2, &y.B2)
	c0 := e.Ext2.Add(&x.B1, &x.B2)
	tmp := e.Ext2.Add(&y.B1, &y.B2)
	c0 = e.Ext2.Mul(c0, tmp)
	c0 = e.Ext2.Sub(c0, t1)
	c0 = e.Ext2.Sub(c0, t2)
	c0 = e.Ext2.MulByNonResidue(c0)
	c0 = e.Ext2.Add(c0, t0)
	c1 := e.Ext2.Add(&x.B0, &x.B1)
	tmp = e.Ext2.Add(&y.B0, &y.B1)
	c1 = e.Ext2.Mul(c1, tmp)
	c1 = e.Ext2.Sub(c1, t0)
	c1 = e.Ext2.Sub(c1, t1)
	tmp = e.Ext2.MulByNonResidue(t2)
	c1 = e.Ext2.Add(c1, tmp)
	tmp = e.Ext2.Add(&x.B0, &x.B2)
	c2 := e.Ext2.Add(&y.B0, &y.B2)
	c2 = e.Ext2.Mul(c2, tmp)
	c2 = e.Ext2.Sub(c2, t0)
	c2 = e.Ext2.Sub(c2, t2)
	c2 = e.Ext2.Add(c2, t1)
	return &E6{
		B0: *c0,
		B1: *c1,
		B2: *c2,
	}
}

func (e Ext6) Double(x *E6) *E6 {
	z0 := e.Ext2.Double(&x.B0)
	z1 := e.Ext2.Double(&x.B1)
	z2 := e.Ext2.Double(&x.B2)
	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) Square(x *E6) *E6 {
	c4 := e.Ext2.Mul(&x.B0, &x.B1)
	c4 = e.Ext2.Double(c4)
	c5 := e.Ext2.Square(&x.B2)
	c1 := e.Ext2.MulByNonResidue(c5)
	c1 = e.Ext2.Add(c1, c4)
	c2 := e.Ext2.Sub(c4, c5)
	c3 := e.Ext2.Square(&x.B0)
	c4 = e.Ext2.Sub(&x.B0, &x.B1)
	c4 = e.Ext2.Add(c4, &x.B2)
	c5 = e.Ext2.Mul(&x.B1, &x.B2)
	c5 = e.Ext2.Double(c5)
	c4 = e.Ext2.Square(c4)
	c0 := e.Ext2.MulByNonResidue(c5)
	c0 = e.Ext2.Add(c0, c3)
	z2 := e.Ext2.Add(c2, c4)
	z2 = e.Ext2.Add(z2, c5)
	z2 = e.Ext2.Sub(z2, c3)
	z0 := c0
	z1 := c1
	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) MulByE2(x *E6, y *E2) *E6 {
	z0 := e.Ext2.Mul(&x.B0, y)
	z1 := e.Ext2.Mul(&x.B1, y)
	z2 := e.Ext2.Mul(&x.B2, y)
	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

// MulBy12 multiplication by sparse element (0,b1,b2)
func (e Ext6) MulBy12(x *E6, b1, b2 *E2) *E6 {
	t1 := e.Ext2.Mul(&x.B1, b1)
	t2 := e.Ext2.Mul(&x.B2, b2)
	c0 := e.Ext2.Add(&x.B1, &x.B2)
	tmp := e.Ext2.Add(b1, b2)
	c0 = e.Ext2.Mul(c0, tmp)
	c0 = e.Ext2.Sub(c0, t1)
	c0 = e.Ext2.Sub(c0, t2)
	c0 = e.Ext2.MulByNonResidue(c0)
	c1 := e.Ext2.Add(&x.B0, &x.B1)
	c1 = e.Ext2.Mul(c1, b1)
	c1 = e.Ext2.Sub(c1, t1)
	tmp = e.Ext2.MulByNonResidue(t2)
	c1 = e.Ext2.Add(c1, tmp)
	tmp = e.Ext2.Add(&x.B0, &x.B2)
	c2 := e.Ext2.Mul(b2, tmp)
	c2 = e.Ext2.Sub(c2, t2)
	c2 = e.Ext2.Add(c2, t1)
	return &E6{
		B0: *c0,
		B1: *c1,
		B2: *c2,
	}
}

// MulBy0 multiplies z by an E6 sparse element of the form
//
//	E6{
//		B0: c0,
//		B1: 0,
//		B2: 0,
//	}
func (e Ext6) MulBy0(z *E6, c0 *E2) *E6 {
	a := e.Ext2.Mul(&z.B0, c0)
	tmp := e.Ext2.Add(&z.B0, &z.B2)
	t2 := e.Ext2.Mul(c0, tmp)
	t2 = e.Ext2.Sub(t2, a)
	tmp = e.Ext2.Add(&z.B0, &z.B1)
	t1 := e.Ext2.Mul(c0, tmp)
	t1 = e.Ext2.Sub(t1, a)
	return &E6{
		B0: *a,
		B1: *t1,
		B2: *t2,
	}
}

// MulBy01 multiplication by sparse element (c0,c1,0)
func (e Ext6) MulBy01(z *E6, c0, c1 *E2) *E6 {
	a := e.Ext2.Mul(&z.B0, c0)
	b := e.Ext2.Mul(&z.B1, c1)
	tmp := e.Ext2.Add(&z.B1, &z.B2)
	t0 := e.Ext2.Mul(c1, tmp)
	t0 = e.Ext2.Sub(t0, b)
	t0 = e.Ext2.MulByNonResidue(t0)
	t0 = e.Ext2.Add(t0, a)
	tmp = e.Ext2.Add(&z.B0, &z.B2)
	t2 := e.Ext2.Mul(c0, tmp)
	t2 = e.Ext2.Sub(t2, a)
	t2 = e.Ext2.Add(t2, b)
	t1 := e.Ext2.Add(c0, c1)
	tmp = e.Ext2.Add(&z.B0, &z.B1)
	t1 = e.Ext2.Mul(t1, tmp)
	t1 = e.Ext2.Sub(t1, a)
	t1 = e.Ext2.Sub(t1, b)
	return &E6{
		B0: *t0,
		B1: *t1,
		B2: *t2,
	}
}

func (e Ext6) MulByNonResidue(x *E6) *E6 {
	z2, z1, z0 := &x.B1, &x.B0, &x.B2
	z0 = e.Ext2.MulByNonResidue(z0)
	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e Ext6) AssertIsEqual(x, y *E6) {
	e.Ext2.AssertIsEqual(&x.B0, &y.B0)
	e.Ext2.AssertIsEqual(&x.B1, &y.B1)
	e.Ext2.AssertIsEqual(&x.B2, &y.B2)
}

func FromE6(y *bls12381.E6) E6 {
	return E6{
		B0: FromE2(&y.B0),
		B1: FromE2(&y.B1),
		B2: FromE2(&y.B2),
	}

}

func (e Ext6) Inverse(x *E6) *E6 {
	res, err := e.fp.NewHint(inverseE6Hint, 6, &x.B0.A0, &x.B0.A1, &x.B1.A0, &x.B1.A1, &x.B2.A0, &x.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	inv := E6{
		B0: E2{A0: *res[0], A1: *res[1]},
		B1: E2{A0: *res[2], A1: *res[3]},
		B2: E2{A0: *res[4], A1: *res[5]},
	}

	one := e.One()

	// 1 == inv * x
	_one := e.Mul(&inv, x)
	e.AssertIsEqual(one, _one)

	return &inv

}

func (e Ext6) DivUnchecked(x, y *E6) *E6 {
	res, err := e.fp.NewHint(divE6Hint, 6, &x.B0.A0, &x.B0.A1, &x.B1.A0, &x.B1.A1, &x.B2.A0, &x.B2.A1, &y.B0.A0, &y.B0.A1, &y.B1.A0, &y.B1.A1, &y.B2.A0, &y.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	div := E6{
		B0: E2{A0: *res[0], A1: *res[1]},
		B1: E2{A0: *res[2], A1: *res[3]},
		B2: E2{A0: *res[4], A1: *res[5]},
	}

	// x == div * y
	_x := e.Mul(&div, y)
	e.AssertIsEqual(x, _x)

	return &div
}

func (e Ext6) Select(selector frontend.Variable, z1, z0 *E6) *E6 {
	b0 := e.Ext2.Select(selector, &z1.B0, &z0.B0)
	b1 := e.Ext2.Select(selector, &z1.B1, &z0.B1)
	b2 := e.Ext2.Select(selector, &z1.B2, &z0.B2)
	return &E6{B0: *b0, B1: *b1, B2: *b2}
}

func (e Ext6) Lookup2(s1, s2 frontend.Variable, a, b, c, d *E6) *E6 {
	b0 := e.Ext2.Lookup2(s1, s2, &a.B0, &b.B0, &c.B0, &d.B0)
	b1 := e.Ext2.Lookup2(s1, s2, &a.B1, &b.B1, &c.B1, &d.B1)
	b2 := e.Ext2.Lookup2(s1, s2, &a.B2, &b.B2, &c.B2, &d.B2)
	return &E6{B0: *b0, B1: *b1, B2: *b2}
}

type E12 struct {
	C0, C1 E6
}

type Ext12 struct {
	*Ext6
}

func NewExt12(api frontend.API) *Ext12 {
	return &Ext12{Ext6: NewExt6(api)}
}

func (e Ext12) Add(x, y *E12) *E12 {
	z0 := e.Ext6.Add(&x.C0, &y.C0)
	z1 := e.Ext6.Add(&x.C1, &y.C1)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) Sub(x, y *E12) *E12 {
	z0 := e.Ext6.Sub(&x.C0, &y.C0)
	z1 := e.Ext6.Sub(&x.C1, &y.C1)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) Conjugate(x *E12) *E12 {
	z1 := e.Ext6.Neg(&x.C1)
	return &E12{
		C0: x.C0,
		C1: *z1,
	}
}

func (e Ext12) Mul(x, y *E12) *E12 {
	a := e.Ext6.Add(&x.C0, &x.C1)
	b := e.Ext6.Add(&y.C0, &y.C1)
	a = e.Ext6.Mul(a, b)
	b = e.Ext6.Mul(&x.C0, &y.C0)
	c := e.Ext6.Mul(&x.C1, &y.C1)
	z1 := e.Ext6.Sub(a, b)
	z1 = e.Ext6.Sub(z1, c)
	z0 := e.Ext6.MulByNonResidue(c)
	z0 = e.Ext6.Add(z0, b)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) Zero() *E12 {
	zero := e.fp.Zero()
	return &E12{
		C0: E6{
			B0: E2{A0: *zero, A1: *zero},
			B1: E2{A0: *zero, A1: *zero},
			B2: E2{A0: *zero, A1: *zero},
		},
		C1: E6{
			B0: E2{A0: *zero, A1: *zero},
			B1: E2{A0: *zero, A1: *zero},
			B2: E2{A0: *zero, A1: *zero},
		},
	}
}

func (e Ext12) One() *E12 {
	z000 := e.fp.One()
	zero := e.fp.Zero()
	return &E12{
		C0: E6{
			B0: E2{A0: *z000, A1: *zero},
			B1: E2{A0: *zero, A1: *zero},
			B2: E2{A0: *zero, A1: *zero},
		},
		C1: E6{
			B0: E2{A0: *zero, A1: *zero},
			B1: E2{A0: *zero, A1: *zero},
			B2: E2{A0: *zero, A1: *zero},
		},
	}
}

func (e Ext12) IsZero(z *E12) frontend.Variable {
	c0 := e.Ext6.IsZero(&z.C0)
	c1 := e.Ext6.IsZero(&z.C1)
	return e.api.And(c0, c1)
}

func (e Ext12) Square(x *E12) *E12 {
	c0 := e.Ext6.Sub(&x.C0, &x.C1)
	c3 := e.Ext6.MulByNonResidue(&x.C1)
	c3 = e.Ext6.Neg(c3)
	c3 = e.Ext6.Add(&x.C0, c3)
	c2 := e.Ext6.Mul(&x.C0, &x.C1)
	c0 = e.Ext6.Mul(c0, c3)
	c0 = e.Ext6.Add(c0, c2)
	z1 := e.Ext6.Double(c2)
	c2 = e.Ext6.MulByNonResidue(c2)
	z0 := e.Ext6.Add(c0, c2)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) AssertIsEqual(x, y *E12) {
	e.Ext6.AssertIsEqual(&x.C0, &y.C0)
	e.Ext6.AssertIsEqual(&x.C1, &y.C1)
}

func FromE12(y *bls12381.E12) E12 {
	return E12{
		C0: FromE6(&y.C0),
		C1: FromE6(&y.C1),
	}

}

func (e Ext12) Inverse(x *E12) *E12 {
	res, err := e.fp.NewHint(inverseE12Hint, 12, &x.C0.B0.A0, &x.C0.B0.A1, &x.C0.B1.A0, &x.C0.B1.A1, &x.C0.B2.A0, &x.C0.B2.A1, &x.C1.B0.A0, &x.C1.B0.A1, &x.C1.B1.A0, &x.C1.B1.A1, &x.C1.B2.A0, &x.C1.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	inv := E12{
		C0: E6{
			B0: E2{A0: *res[0], A1: *res[1]},
			B1: E2{A0: *res[2], A1: *res[3]},
			B2: E2{A0: *res[4], A1: *res[5]},
		},
		C1: E6{
			B0: E2{A0: *res[6], A1: *res[7]},
			B1: E2{A0: *res[8], A1: *res[9]},
			B2: E2{A0: *res[10], A1: *res[11]},
		},
	}

	one := e.One()

	// 1 == inv * x
	_one := e.Mul(&inv, x)
	e.AssertIsEqual(one, _one)

	return &inv

}

func (e Ext12) DivUnchecked(x, y *E12) *E12 {
	res, err := e.fp.NewHint(divE12Hint, 12, &x.C0.B0.A0, &x.C0.B0.A1, &x.C0.B1.A0, &x.C0.B1.A1, &x.C0.B2.A0, &x.C0.B2.A1, &x.C1.B0.A0, &x.C1.B0.A1, &x.C1.B1.A0, &x.C1.B1.A1, &x.C1.B2.A0, &x.C1.B2.A1, &y.C0.B0.A0, &y.C0.B0.A1, &y.C0.B1.A0, &y.C0.B1.A1, &y.C0.B2.A0, &y.C0.B2.A1, &y.C1.B0.A0, &y.C1.B0.A1, &y.C1.B1.A0, &y.C1.B1.A1, &y.C1.B2.A0, &y.C1.B2.A1)

	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	div := E12{
		C0: E6{
			B0: E2{A0: *res[0], A1: *res[1]},
			B1: E2{A0: *res[2], A1: *res[3]},
			B2: E2{A0: *res[4], A1: *res[5]},
		},
		C1: E6{
			B0: E2{A0: *res[6], A1: *res[7]},
			B1: E2{A0: *res[8], A1: *res[9]},
			B2: E2{A0: *res[10], A1: *res[11]},
		},
	}

	// x == div * y
	_x := e.Mul(&div, y)
	e.AssertIsEqual(x, _x)

	return &div
}

func (e Ext12) Select(selector frontend.Variable, z1, z0 *E12) *E12 {
	c0 := e.Ext6.Select(selector, &z1.C0, &z0.C0)
	c1 := e.Ext6.Select(selector, &z1.C1, &z0.C1)
	return &E12{C0: *c0, C1: *c1}
}

func (e Ext12) Lookup2(s1, s2 frontend.Variable, a, b, c, d *E12) *E12 {
	c0 := e.Ext6.Lookup2(s1, s2, &a.C0, &b.C0, &c.C0, &d.C0)
	c1 := e.Ext6.Lookup2(s1, s2, &a.C1, &b.C1, &c.C1, &d.C1)
	return &E12{C0: *c0, C1: *c1}
}

func (e Ext12) nSquareTorus(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.SquareTorus(z)
	}
	return z
}

// ExptHalfTorus set z to x^(t/2) in E6 and return z
// const t/2 uint64 = 7566188111470821376 // negative
func (e Ext12) ExptHalfTorus(x *E6) *E6 {
	// FixedExp computation is derived from the addition chain:
	//
	//	_10      = 2*1
	//	_11      = 1 + _10
	//	_1100    = _11 << 2
	//	_1101    = 1 + _1100
	//	_1101000 = _1101 << 3
	//	_1101001 = 1 + _1101000
	//	return     ((_1101001 << 9 + 1) << 32 + 1) << 15
	//
	// Operations: 62 squares 5 multiplies
	//
	// Generated by github.com/mmcloughlin/addchain v0.4.0.

	// Step 1: z = x^0x2
	z := e.SquareTorus(x)

	// Step 2: z = x^0x3
	z = e.MulTorus(x, z)

	z = e.SquareTorus(z)
	z = e.SquareTorus(z)

	// Step 5: z = x^0xd
	z = e.MulTorus(x, z)

	// Step 8: z = x^0x68
	z = e.nSquareTorus(z, 3)

	// Step 9: z = x^0x69
	z = e.MulTorus(x, z)

	// Step 18: z = x^0xd200
	z = e.nSquareTorus(z, 9)

	// Step 19: z = x^0xd201
	z = e.MulTorus(x, z)

	// Step 51: z = x^0xd20100000000
	z = e.nSquareTorus(z, 32)

	// Step 52: z = x^0xd20100000001
	z = e.MulTorus(x, z)

	// Step 67: z = x^0x6900800000008000
	z = e.nSquareTorus(z, 15)

	z = e.InverseTorus(z) // because tAbsVal is negative

	return z
}

// ExptTorus set z to xᵗ in E6 and return z
// const t uint64 = 15132376222941642752 // negative
func (e Ext12) ExptTorus(x *E6) *E6 {
	z := e.ExptHalfTorus(x)
	z = e.SquareTorus(z)
	return z
}

// MulBy014 multiplies z by an E12 sparse element of the form
//
//	E12{
//		C0: E6{B0: c0, B1: c1, B2: 0},
//		C1: E6{B0: 0, B1: 1, B2: 0},
//	}
func (e *Ext12) MulBy014(z *E12, c0, c1 *E2) *E12 {

	a := z.C0
	a = *e.MulBy01(&a, c0, c1)

	var b E6
	// Mul by E6{0, 1, 0}
	b.B0 = *e.Ext2.MulByNonResidue(&z.C1.B2)
	b.B2 = z.C1.B1
	b.B1 = z.C1.B0

	one := e.Ext2.One()
	d := e.Ext2.Add(c1, one)

	zC1 := e.Ext6.Add(&z.C1, &z.C0)
	zC1 = e.Ext6.MulBy01(zC1, c0, d)
	zC1 = e.Ext6.Sub(zC1, &a)
	zC1 = e.Ext6.Sub(zC1, &b)
	zC0 := e.Ext6.MulByNonResidue(&b)
	zC0 = e.Ext6.Add(zC0, &a)

	return &E12{
		C0: *zC0,
		C1: *zC1,
	}
}

//	multiplies two E12 sparse element of the form:
//
//	E12{
//		C0: E6{B0: c0, B1: c1, B2: 0},
//		C1: E6{B0: 0, B1: 1, B2: 0},
//	}
//
// and
//
//	E12{
//		C0: E6{B0: d0, B1: d1, B2: 0},
//		C1: E6{B0: 0, B1: 1, B2: 0},
//	}
func (e Ext12) Mul014By014(d0, d1, c0, c1 *E2) *[5]E2 {
	one := e.Ext2.One()
	x0 := e.Ext2.Mul(c0, d0)
	x1 := e.Ext2.Mul(c1, d1)
	tmp := e.Ext2.Add(c0, one)
	x04 := e.Ext2.Add(d0, one)
	x04 = e.Ext2.Mul(x04, tmp)
	x04 = e.Ext2.Sub(x04, x0)
	x04 = e.Ext2.Sub(x04, one)
	tmp = e.Ext2.Add(c0, c1)
	x01 := e.Ext2.Add(d0, d1)
	x01 = e.Ext2.Mul(x01, tmp)
	x01 = e.Ext2.Sub(x01, x0)
	x01 = e.Ext2.Sub(x01, x1)
	tmp = e.Ext2.Add(c1, one)
	x14 := e.Ext2.Add(d1, one)
	x14 = e.Ext2.Mul(x14, tmp)
	x14 = e.Ext2.Sub(x14, x1)
	x14 = e.Ext2.Sub(x14, one)

	zC0B0 := e.Ext2.NonResidue()
	zC0B0 = e.Ext2.Add(zC0B0, x0)

	return &[5]E2{*zC0B0, *x01, *x1, *x04, *x14}
}

// MulBy01245 multiplies z by an E12 sparse element of the form
//
//	E12{
//		C0: E6{B0: c0, B1: c1, B2: c2},
//		C1: E6{B0: 0, B1: c4, B2: c5},
//	}
func (e *Ext12) MulBy01245(z *E12, x *[5]E2) *E12 {
	c0 := &E6{B0: x[0], B1: x[1], B2: x[2]}
	c1 := &E6{B0: *e.Ext2.Zero(), B1: x[3], B2: x[4]}
	a := e.Ext6.Add(&z.C0, &z.C1)
	b := e.Ext6.Add(c0, c1)
	a = e.Ext6.Mul(a, b)
	b = e.Ext6.Mul(&z.C0, c0)
	c := e.Ext6.MulBy12(&z.C1, &x[3], &x[4])
	z1 := e.Ext6.Sub(a, b)
	z1 = e.Ext6.Sub(z1, c)
	z0 := e.Ext6.MulByNonResidue(c)
	z0 = e.Ext6.Add(z0, b)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

// Torus-based arithmetic:
//
// After the easy part of the final exponentiation the elements are in a proper
// subgroup of Fpk (E12) that coincides with some algebraic tori. The elements
// are in the torus Tk(Fp) and thus in each torus Tk/d(Fp^d) for d|k, d≠k.  We
// take d=6. So the elements are in T2(Fp6).
// Let G_{q,2} = {m ∈ Fq^2 | m^(q+1) = 1} where q = p^6.
// When m.C1 = 0, then m.C0 must be 1 or −1.
//
// We recall the tower construction:
//
//	𝔽p²[u] = 𝔽p/u²+1
//	𝔽p⁶[v] = 𝔽p²/v³-1-u
//	𝔽p¹²[w] = 𝔽p⁶/w²-v

// CompressTorus compresses x ∈ E12 to (x.C0 + 1)/x.C1 ∈ E6
func (e Ext12) CompressTorus(x *E12) *E6 {
	// x ∈ G_{q,2} \ {-1,1}
	y := e.Ext6.Add(&x.C0, e.Ext6.One())
	y = e.Ext6.DivUnchecked(y, &x.C1)
	return y
}

// DecompressTorus decompresses y ∈ E6 to (y+w)/(y-w) ∈ E12
func (e Ext12) DecompressTorus(y *E6) *E12 {
	var n, d E12
	one := e.Ext6.One()
	n.C0 = *y
	n.C1 = *one
	d.C0 = *y
	d.C1 = *e.Ext6.Neg(one)

	x := e.DivUnchecked(&n, &d)
	return x
}

// MulTorus multiplies two compressed elements y1, y2 ∈ E6
// and returns (y1 * y2 + v)/(y1 + y2)
// N.B.: we use MulTorus in the final exponentiation throughout y1 ≠ -y2 always.
func (e Ext12) MulTorus(y1, y2 *E6) *E6 {
	n := e.Ext6.Mul(y1, y2)
	n.B1 = *e.Ext2.Add(&n.B1, e.Ext2.One())
	d := e.Ext6.Add(y1, y2)
	y3 := e.Ext6.DivUnchecked(n, d)
	return y3
}

// InverseTorus inverses a compressed elements y ∈ E6
// and returns -y
func (e Ext12) InverseTorus(y *E6) *E6 {
	return e.Ext6.Neg(y)
}

// SquareTorus squares a compressed elements y ∈ E6
// and returns (y + v/y)/2
//
// It uses a hint to verify that (2x-y)y = v saving one E6 AssertIsEqual.
func (e Ext12) SquareTorus(y *E6) *E6 {
	res, err := e.fp.NewHint(squareTorusHint, 6, &y.B0.A0, &y.B0.A1, &y.B1.A0, &y.B1.A1, &y.B2.A0, &y.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	sq := E6{
		B0: E2{A0: *res[0], A1: *res[1]},
		B1: E2{A0: *res[2], A1: *res[3]},
		B2: E2{A0: *res[4], A1: *res[5]},
	}

	// v = (2x-y)y
	v := e.Ext6.Double(&sq)
	v = e.Ext6.Sub(v, y)
	v = e.Ext6.Mul(v, y)

	_v := E6{B0: *e.Ext2.Zero(), B1: *e.Ext2.One(), B2: *e.Ext2.Zero()}
	e.Ext6.AssertIsEqual(v, &_v)

	return &sq

}

// FrobeniusTorus raises a compressed elements y ∈ E6 to the modulus p
// and returns y^p / v^((p-1)/2)
func (e Ext12) FrobeniusTorus(y *E6) *E6 {
	t0 := e.Ext2.Conjugate(&y.B0)
	t1 := e.Ext2.Conjugate(&y.B1)
	t2 := e.Ext2.Conjugate(&y.B2)
	t1 = e.Ext2.MulByNonResidue1Power2(t1)
	t2 = e.Ext2.MulByNonResidue1Power4(t2)

	v0 := E2{emulated.ValueOf[emulated.BLS12381Fp]("877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230"), emulated.ValueOf[emulated.BLS12381Fp]("877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230")}
	res := &E6{B0: *t0, B1: *t1, B2: *t2}
	res = e.Ext6.MulBy0(res, &v0)

	return res
}

// FrobeniusSquareTorus raises a compressed elements y ∈ E6 to the square modulus p^2
// and returns y^(p^2) / v^((p^2-1)/2)
func (e Ext12) FrobeniusSquareTorus(y *E6) *E6 {
	v0 := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437")
	t0 := e.Ext2.MulByElement(&y.B0, &v0)
	t1 := e.Ext2.MulByNonResidue2Power2(&y.B1)
	t1 = e.Ext2.MulByElement(t1, &v0)
	t2 := e.Ext2.MulByNonResidue2Power4(&y.B2)
	t2 = e.Ext2.MulByElement(t2, &v0)

	return &E6{B0: *t0, B1: *t1, B2: *t2}
}
