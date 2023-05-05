# ZKHackathon: zkCircuits
<img width="432" alt="Screenshot 2023-04-29 at 21 34 36" src="https://user-images.githubusercontent.com/16170090/235321077-c409674c-3f08-40bd-be8c-54e660bb1225.png">

This repository contains a submission to the [ZKP/Web3 Hackathon](https://zk-hacking.org/) hosted by Berkeley RDI.

This is the `sowa3dowa` team submission to the zkCircuits track for tasks 1.3, 1.4 and 2.1. A description of this tasks can be found in this [document](https://drive.google.com/file/d/1iQ7Cl0OjeL_Rrwkn7zRGDjb6dp0O4QfG/view).

The submission is written in Go, and is based on gnark SNARK library.

## Video
[<img width="1440" alt="image" src="https://user-images.githubusercontent.com/16170090/235320848-b3087abc-9a93-4fcc-831f-834158ef7c00.png">](https://youtu.be/2-hvcQNf69Q)

## Pre-requisites
Install [Go 1.20](https://go.dev/doc/install) (latest version).

## Test
The project comes with unit tests from gnark project in addition to tests for the new functions. To run all the tests, at the root repo, run: `go test -v ./...`

## Benchmark
At the root repo, run: `go test -v ./... -run=NONE  -bench=./....`


- Category 1: Circuits/R1CSs for cryptographic primitives
  - Designated Task 1.3: BLS signature
```js
⏱️  Single BLS12-381 pairing in a BN254 R1CS circuit:  2088277
⏱️  Single BLS12-381 pairing (fixed G2 argument) in a BN254 R1CS circuit:  1868541
⏱️  Single BN254 pairing in a BN254 R1CS circuit:  1393318
⏱️  Single BN254 pairing (fixed G2 argument) in a BN254 R1CS circuit:  1223891

⏱️  BLS signature verifier on BLS12-381 in a BN254 R1CS circuit (v1):  2682079
⏱️  BLS signature verifier on BLS12-381 in a BN254 R1CS circuit (v2):  2456762
⏱️  BLS signature verifier on BN254 in a BN254 R1CS circuit (v1):  1875862
⏱️  BLS signature verifier on BN254 in a BN254 R1CS circuit (v2):  1874689
```
_(*) v1: Minimal-pubkey-size variant. Public keys are points in G1, signatures are points in G2._

_(*) v2: Minimal-signature-size variant: signatures are points in G1, public keys are points in G2._

- Category 1: Circuits/R1CSs for cryptographic primitives
  - Designated Task 1.4: ECDSA signature
```js
⏱️  ECDSA on secp256k1 verifier in a BN254 R1CS circuit:  379842 constraints.
```

- Category 2: Circuits/R1CSs for recursive SNARKs
  - Designated Task 2.1: Cycles of elliptic curves: BLS12-377 to BW6-761
```js
⏱️  Single pairing on BLS12-377 in a BW6-761 R1CS circuit:  11582
```

## Techniques
- For pairings (BLS12-377, BN254 and BL12-381) we follow [[Housni22]](https://eprint.iacr.org/2022/1162). Mainly we write G2 arithmetic in affine coordinates and use [[ELM03]](https://arxiv.org/pdf/math/0208038.pdf) to optimize the formulas of Double-And-Add and Triple. We multiply the lines `R0*y+R1*x+R2=0` by `1/(R0*y)` (which is killed later by the final exponentiation) to store only two line coefficients and make the sparse-multiplication in `Fp12` even more efficient constraint-wise. We isolate the first two iterations in the Miller loop to avoid a squaring and a plain multiplication in the full extension. We also isolate the last iteration to save a doubling/addition step as we only need the resulting line and not the resulting point. We also multiply the lines 2-by-2 to exploit sparsity in `Fp12` to its fullest.
- For the minimal-pubkey-size variant of BLS signature v2 (or also the KZG polynomial commitment), we write a special Miller loop circuit that uses precomputations. In fact, in the ate Miller loop all the doublings, additions and line computations are avoided — we precompute all the lines and only evaluate them in the first argument inside the circuit. This saves ~170k R1CS for a single pairing. We combine this idea with the Miller loop of arbitrary arguments to share the accumulator squarings in `Fp12` between the two instances of the Miller loops.
- For the final exponentiation, we completely implement it for BN254 and BLS12-381 using torus-based arithmetic. This allows us to write constraints in `Fp6` instead of `Fp12`. We derive formulas of multiplication, squaring, Frobenius exponentiations following [[CEILIDH]](https://www.math.uci.edu/~asilverb/bibliography/ceilidh.pdf). We absorb the compression cost at the easy part stage as in [[NBP08]](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/ocpatc.pdf) and deal with -1/1 edge cases with an R1CS-select logic. The cost is almost divided by 3. This was not worth it for BLS12-377 as we use [[Karabina10]](https://eprint.iacr.org/2010/542.pdf) cyclotomic squaring for the repeated 46 squarings — which is better than torus-squaring for this size.
- For tower fields, we use Karabina and Toom-cook multiplication routines. We use hints (out-circuit computation + in-circuit verification) whenever possible (Inverse, Division, Torus-square...). The dominant cost in the final exponentiation is the exponentiation by the curve seed (constant), which we write efficiently using an optimized addition chain generated using [[mmcloughlin/addchain]](https://github.com/mmcloughlin/addchain).
- For ECDSA, the bottlneck is 2 scalar multiplications, one of which is with the fixed canonical generator point. We use a right-to-left double-and-add method so that we repeatedly double the input point and not the accumulator. We assume that the first bit is 1 so that we start the loop with the input point rather than the infinity point. We use affine incomplete doubling and addition formulas and at the end we subtract the input point if the first bit was 0. For the scalar multiplication by the fixed canonical generator, we pre-compute all the doublings and only do additions in-circuit. When we want to deal with edge cases, we implemented [[BrierJoye06]](https://www.iacr.org/archive/ches2006/28/28.pdf) unified addition which works the same for both doubling and adding points.
