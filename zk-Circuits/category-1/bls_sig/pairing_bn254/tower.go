package pairing_bn254

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type curveF = emulated.Field[emulated.BN254Fp]
type baseEl = emulated.Element[emulated.BN254Fp]

type E2 struct {
	A0, A1 baseEl
}

type Ext2 struct {
	api         frontend.API
	fp          *curveF
	nonResidues map[int]map[int]*E2
}

func NewExt2(api frontend.API) *Ext2 {
	fp, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		panic(err)
	}
	pwrs := map[int]map[int]struct {
		A0 string
		A1 string
	}{
		1: {
			1: {"8376118865763821496583973867626364092589906065868298776909617916018768340080", "16469823323077808223889137241176536799009286646108169935659301613961712198316"},
			2: {"21575463638280843010398324269430826099269044274347216827212613867836435027261", "10307601595873709700152284273816112264069230130616436755625194854815875713954"},
			3: {"2821565182194536844548159561693502659359617185244120367078079554186484126554", "3505843767911556378687030309984248845540243509899259641013678093033130930403"},
			4: {"2581911344467009335267311115468803099551665605076196740867805258568234346338", "19937756971775647987995932169929341994314640652964949448313374472400716661030"},
			5: {"685108087231508774477564247770172212460312782337200605669322048753928464687", "8447204650696766136447902020341177575205426561248465145919723016860428151883"},
		},
		3: {
			1: {"11697423496358154304825782922584725312912383441159505038794027105778954184319", "303847389135065887422783454877609941456349188919719272345083954437860409601"},
			2: {"3772000881919853776433695186713858239009073593817195771773381919316419345261", "2236595495967245188281701248203181795121068902605861227855261137820944008926"},
			3: {"19066677689644738377698246183563772429336693972053703295610958340458742082029", "18382399103927718843559375435273026243156067647398564021675359801612095278180"},
			4: {"5324479202449903542726783395506214481928257762400643279780343368557297135718", "16208900380737693084919495127334387981393726419856888799917914180988844123039"},
			5: {"8941241848238582420466759817324047081148088512956452953208002715982955420483", "10338197737521362862238855242243140895517409139741313354160881284257516364953"},
		},
	}
	nonResidues := make(map[int]map[int]*E2)
	for pwr, v := range pwrs {
		for coeff, v := range v {
			el := E2{emulated.ValueOf[emulated.BN254Fp](v.A0), emulated.ValueOf[emulated.BN254Fp](v.A1)}
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

// MulByNonResidue return x*(9+u)
func (e Ext2) MulByNonResidue(x *E2) *E2 {
	nine := big.NewInt(9)
	a := e.fp.MulConst(&x.A0, nine)
	a = e.fp.Sub(a, &x.A1)
	b := e.fp.MulConst(&x.A1, nine)
	b = e.fp.Add(b, &x.A0)
	return &E2{
		A0: *a,
		A1: *b,
	}
}

// MulByNonResidue1Power1 returns x*(9+u)^(1*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power1(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 1)
}

// MulByNonResidue1Power2 returns x*(9+u)^(2*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power2(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 2)
}

// MulByNonResidue1Power3 returns x*(9+u)^(3*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power3(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 3)
}

// MulByNonResidue1Power4 returns x*(9+u)^(4*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power4(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 4)
}

// MulByNonResidue1Power5 returns x*(9+u)^(5*(p^1-1)/6)
func (e Ext2) MulByNonResidue1Power5(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 1, 5)
}

// MulByNonResidue2Power1 returns x*(9+u)^(1*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power1(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BN254Fp]("21888242871839275220042445260109153167277707414472061641714758635765020556617")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue2Power2 returns x*(9+u)^(2*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power2(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BN254Fp]("21888242871839275220042445260109153167277707414472061641714758635765020556616")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue2Power3 returns x*(9+u)^(3*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power3(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BN254Fp]("21888242871839275222246405745257275088696311157297823662689037894645226208582")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue2Power4 returns x*(9+u)^(4*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power4(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BN254Fp]("2203960485148121921418603742825762020974279258880205651966")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue2Power5 returns x*(9+u)^(5*(p^2-1)/6)
func (e Ext2) MulByNonResidue2Power5(x *E2) *E2 {
	element := emulated.ValueOf[emulated.BN254Fp]("2203960485148121921418603742825762020974279258880205651967")
	return &E2{
		A0: *e.fp.MulMod(&x.A0, &element),
		A1: *e.fp.MulMod(&x.A1, &element),
	}
}

// MulByNonResidue3Power1 returns x*(9+u)^(1*(p^3-1)/6)
func (e Ext2) MulByNonResidue3Power1(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 1)
}

// MulByNonResidue3Power2 returns x*(9+u)^(2*(p^3-1)/6)
func (e Ext2) MulByNonResidue3Power2(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 2)
}

// MulByNonResidue3Power3 returns x*(9+u)^(3*(p^3-1)/6)
func (e Ext2) MulByNonResidue3Power3(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 3)
}

// MulByNonResidue3Power4 returns x*(9+u)^(4*(p^3-1)/6)
func (e Ext2) MulByNonResidue3Power4(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 4)
}

// MulByNonResidue3Power5 returns x*(9+u)^(5*(p^3-1)/6)
func (e Ext2) MulByNonResidue3Power5(x *E2) *E2 {
	return e.MulByNonResidueGeneric(x, 3, 5)
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

func FromE2(y *bn254.E2) E2 {
	return E2{
		A0: emulated.ValueOf[emulated.BN254Fp](y.A0),
		A1: emulated.ValueOf[emulated.BN254Fp](y.A1),
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

// MulBy01 multiplies z by an E6 sparse element of the form
//
//	E6{
//		B0: c0,
//		B1: c1,
//		B2: 0,
//	}
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

// Mul01By01 multiplies two E6 sparse element of the form:
//
//	E6{
//		B0: c0,
//		B1: c1,
//		B2: 0,
//	}
//
// and
//
//	E6{
//		B0: d0,
//		B1: d1,
//		B2: 0,
//	}
func (e Ext6) Mul01By01(c0, c1, d0, d1 *E2) *E6 {
	a := e.Ext2.Mul(d0, c0)
	b := e.Ext2.Mul(d1, c1)
	t0 := e.Ext2.Mul(c1, d1)
	t0 = e.Ext2.Sub(t0, b)
	t0 = e.Ext2.MulByNonResidue(t0)
	t0 = e.Ext2.Add(t0, a)
	t2 := e.Ext2.Mul(c0, d0)
	t2 = e.Ext2.Sub(t2, a)
	t2 = e.Ext2.Add(t2, b)
	t1 := e.Ext2.Add(c0, c1)
	tmp := e.Ext2.Add(d0, d1)
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

func (e Ext6) FrobeniusSquare(x *E6) *E6 {
	z01 := e.Ext2.MulByNonResidue2Power2(&x.B1)
	z02 := e.Ext2.MulByNonResidue2Power4(&x.B2)
	return &E6{B0: x.B0, B1: *z01, B2: *z02}
}

func (e Ext6) AssertIsEqual(x, y *E6) {
	e.Ext2.AssertIsEqual(&x.B0, &y.B0)
	e.Ext2.AssertIsEqual(&x.B1, &y.B1)
	e.Ext2.AssertIsEqual(&x.B2, &y.B2)
}

func FromE6(y *bn254.E6) E6 {
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

func FromE12(y *bn254.E12) E12 {
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

// Exponentiation by the seed t=4965661367192848881
// The computations are performed on E6 compressed form using Torus-based arithmetic.
func (e Ext12) ExptTorus(x *E6) *E6 {
	// Expt computation is derived from the addition chain:
	//
	//	_10     = 2*1
	//	_100    = 2*_10
	//	_1000   = 2*_100
	//	_10000  = 2*_1000
	//	_10001  = 1 + _10000
	//	_10011  = _10 + _10001
	//	_10100  = 1 + _10011
	//	_11001  = _1000 + _10001
	//	_100010 = 2*_10001
	//	_100111 = _10011 + _10100
	//	_101001 = _10 + _100111
	//	i27     = (_100010 << 6 + _100 + _11001) << 7 + _11001
	//	i44     = (i27 << 8 + _101001 + _10) << 6 + _10001
	//	i70     = ((i44 << 8 + _101001) << 6 + _101001) << 10
	//	return    (_100111 + i70) << 6 + _101001 + _1000
	//
	// Operations: 62 squares 17 multiplies
	//
	// Generated by github.com/mmcloughlin/addchain v0.4.0.

	t3 := e.SquareTorus(x)
	t5 := e.SquareTorus(t3)
	result := e.SquareTorus(t5)
	t0 := e.SquareTorus(result)
	t2 := e.MulTorus(x, t0)
	t0 = e.MulTorus(t3, t2)
	t1 := e.MulTorus(x, t0)
	t4 := e.MulTorus(result, t2)
	t6 := e.SquareTorus(t2)
	t1 = e.MulTorus(t0, t1)
	t0 = e.MulTorus(t3, t1)
	t6 = e.nSquareTorus(t6, 6)
	t5 = e.MulTorus(t5, t6)
	t5 = e.MulTorus(t4, t5)
	t5 = e.nSquareTorus(t5, 7)
	t4 = e.MulTorus(t4, t5)
	t4 = e.nSquareTorus(t4, 8)
	t4 = e.MulTorus(t0, t4)
	t3 = e.MulTorus(t3, t4)
	t3 = e.nSquareTorus(t3, 6)
	t2 = e.MulTorus(t2, t3)
	t2 = e.nSquareTorus(t2, 8)
	t2 = e.MulTorus(t0, t2)
	t2 = e.nSquareTorus(t2, 6)
	t2 = e.MulTorus(t0, t2)
	t2 = e.nSquareTorus(t2, 10)
	t1 = e.MulTorus(t1, t2)
	t1 = e.nSquareTorus(t1, 6)
	t0 = e.MulTorus(t0, t1)
	z := e.MulTorus(result, t0)
	return z
}

// MulBy034 multiplies z by an E12 sparse element of the form
//
//	E12{
//		C0: E6{B0: 1, B1: 0, B2: 0},
//		C1: E6{B0: c3, B1: c4, B2: 0},
//	}
func (e *Ext12) MulBy034(z *E12, c3, c4 *E2) *E12 {

	a := z.C0
	b := z.C1
	b = *e.MulBy01(&b, c3, c4)
	c3 = e.Ext2.Add(e.Ext2.One(), c3)
	d := e.Ext6.Add(&z.C0, &z.C1)
	d = e.MulBy01(d, c3, c4)

	zC1 := e.Ext6.Add(&a, &b)
	zC1 = e.Ext6.Neg(zC1)
	zC1 = e.Ext6.Add(zC1, d)
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
//		C0: E6{B0: 1, B1: 0, B2: 0},
//		C1: E6{B0: c3, B1: c4, B2: 0},
//	}
//
// and
//
//	E12{
//		C0: E6{B0: 1, B1: 0, B2: 0},
//		C1: E6{B0: d3, B1: d4, B2: 0},
//	}
func (e *Ext12) Mul034By034(d3, d4, c3, c4 *E2) *[5]E2 {
	x3 := e.Ext2.Mul(c3, d3)
	x4 := e.Ext2.Mul(c4, d4)
	x04 := e.Ext2.Add(c4, d4)
	x03 := e.Ext2.Add(c3, d3)
	tmp := e.Ext2.Add(c3, c4)
	x34 := e.Ext2.Add(d3, d4)
	x34 = e.Ext2.Mul(x34, tmp)
	x34 = e.Ext2.Sub(x34, x3)
	x34 = e.Ext2.Sub(x34, x4)

	zC0B0 := e.Ext2.MulByNonResidue(x4)
	zC0B0 = e.Ext2.Add(zC0B0, e.Ext2.One())
	zC0B1 := x3
	zC0B2 := x34
	zC1B0 := x03
	zC1B1 := x04

	return &[5]E2{*zC0B0, *zC0B1, *zC0B2, *zC1B0, *zC1B1}
}

// MulBy01234 multiplies z by an E12 sparse element of the form
//
//	E12{
//		C0: E6{B0: c0, B1: c1, B2: c2},
//		C1: E6{B0: c3, B1: c4, B2: 0},
//	}
func (e *Ext12) MulBy01234(z *E12, x *[5]E2) *E12 {
	c0 := &E6{B0: x[0], B1: x[1], B2: x[2]}
	c1 := &E6{B0: x[3], B1: x[4], B2: *e.Ext2.Zero()}
	a := e.Ext6.Add(&z.C0, &z.C1)
	b := e.Ext6.Add(c0, c1)
	a = e.Ext6.Mul(a, b)
	b = e.Ext6.Mul(&z.C0, c0)
	c := e.Ext6.MulBy01(&z.C1, &x[3], &x[4])
	z1 := e.Ext6.Sub(a, b)
	z1 = e.Ext6.Sub(z1, c)
	z0 := e.Ext6.MulByNonResidue(c)
	z0 = e.Ext6.Add(z0, b)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

//	multiplies two E12 sparse element of the form:
//
//	E12{
//		C0: E6{B0: x0, B1: x1, B2: x2},
//		C1: E6{B0: x3, B1: x4, B2: 0},
//	}
//
// and
//
//	E12{
//		C0: E6{B0: 1, B1: 0, B2: 0},
//		C1: E6{B0: z3, B1: z4, B2: 0},
//	}
func (e *Ext12) Mul01234By034(x *[5]E2, z3, z4 *E2) *E12 {
	c0 := &E6{B0: x[0], B1: x[1], B2: x[2]}
	c1 := &E6{B0: x[3], B1: x[4], B2: *e.Ext2.Zero()}
	a := e.Ext6.Add(e.Ext6.One(), &E6{B0: *z3, B1: *z4, B2: *e.Ext2.Zero()})
	b := e.Ext6.Add(c0, c1)
	a = e.Ext6.Mul(a, b)
	c := e.Ext6.Mul01By01(z3, z4, &x[3], &x[4])
	z1 := e.Ext6.Sub(a, c0)
	z1 = e.Ext6.Sub(z1, c)
	z0 := e.Ext6.MulByNonResidue(c)
	z0 = e.Ext6.Add(z0, c0)
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
//	𝔽p⁶[v] = 𝔽p²/v³-9-u
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

	v0 := E2{emulated.ValueOf[emulated.BN254Fp]("18566938241244942414004596690298913868373833782006617400804628704885040364344"), emulated.ValueOf[emulated.BN254Fp]("5722266937896532885780051958958348231143373700109372999374820235121374419868")}
	res := &E6{B0: *t0, B1: *t1, B2: *t2}
	res = e.Ext6.MulBy0(res, &v0)

	return res
}

// FrobeniusSquareTorus raises a compressed elements y ∈ E6 to the square modulus p^2
// and returns y^(p^2) / v^((p^2-1)/2)
func (e Ext12) FrobeniusSquareTorus(y *E6) *E6 {
	v0 := emulated.ValueOf[emulated.BN254Fp]("2203960485148121921418603742825762020974279258880205651967")
	t0 := e.Ext2.MulByElement(&y.B0, &v0)
	t1 := e.Ext2.MulByNonResidue2Power2(&y.B1)
	t1 = e.Ext2.MulByElement(t1, &v0)
	t2 := e.Ext2.MulByNonResidue2Power4(&y.B2)
	t2 = e.Ext2.MulByElement(t2, &v0)

	return &E6{B0: *t0, B1: *t1, B2: *t2}
}

// FrobeniusCubeTorus raises a compressed elements y ∈ E6 to the cube modulus p^3
// and returns y^(p^3) / v^((p^3-1)/2)
func (e Ext12) FrobeniusCubeTorus(y *E6) *E6 {
	t0 := e.Ext2.Conjugate(&y.B0)
	t1 := e.Ext2.Conjugate(&y.B1)
	t2 := e.Ext2.Conjugate(&y.B2)
	t1 = e.Ext2.MulByNonResidue3Power2(t1)
	t2 = e.Ext2.MulByNonResidue3Power4(t2)

	v0 := E2{emulated.ValueOf[emulated.BN254Fp]("10190819375481120917420622822672549775783927716138318623895010788866272024264"), emulated.ValueOf[emulated.BN254Fp]("303847389135065887422783454877609941456349188919719272345083954437860409601")}
	res := &E6{B0: *t0, B1: *t1, B2: *t2}
	res = e.Ext6.MulBy0(res, &v0)

	return res
}

// debug
func (e Ext2) String(x *E2) string {
	x0 := e.fp.String(&x.A0)
	x1 := e.fp.String(&x.A1)
	return fmt.Sprintf("%s+%s*u", x0, x1)
}
