# ZKHackathon-zkCircuits
Submission to zk-Circuits track of the ZKP/Web3 Hackathon hosted by Berkeley RDI.

The submission is written in Go, and based gnark SNARK library.

## Pre-requisites
Install [Go 1.19](https://go.dev/doc/install) (latest version).

## Benchmark
At the root repo, run: `go test -v ./... -run=NONE  -bench=./....`

```
⏱️  Single BLS12-381 pairing in a BN254 R1CS circuit:  2088277
⏱️  Single BN254 pairing in a BN254 R1CS circuit:  1393318
⏱️  Single BN254 pairing (fixed G2 argument) in a BN254 R1CS circuit:  1223891

⏱️  BLS signature verifier on BLS12-381 in a BN254 R1CS circuit:  2682079
⏱️  BLS signature verifier on BN254 in a BN254 R1CS circuit (v1):  1875862
⏱️  BLS signature verifier on BN254 in a BN254 R1CS circuit (v2):  1874689

⏱️  ECDSA on secp256k1 verifier in a BN254 R1CS circuit:  379842 constraints.

⏱️  Single pairing on BLS12-377 in a BW6-761 R1CS circuit:  11582
```

## Techniques
- For pairings (BLS12-377, BN254 and BL12-381) we follow [Housni22](https://eprint.iacr.org/2022/1162). Mainly we write G2 arithmetic in affine coordinates and use [ELM03](https://arxiv.org/pdf/math/0208038.pdf) to optimize the formulas of Double-And-Add. We multiply the line `R0*y+R1*x+R2=0` by `1/(R0*y)` (which is killed later by the final exponentiation) to store only two line coefficients and make the sparse-multiplication even more efficient constraint-wise. We isolate the first two iterations in the Miller loop to avoid a squaring and a plain multiplication in the full extension. We also isolate the last iteration to save a doubling/addition step as we only need the resulting line and not the resulting point. We also multiply the lines 2-by-2 to exploit sparcity to its fullest.
- For the minimal-pubkey-size variant of BLS signature (or also the KZG polynomial commitment), we write a special Miller loop circuit that uses precomputations. In fact, in the ate Miller loop all the doublings, additions and line computations are avoided — we precompute all the lines and only evaluate them in the first argument inside the circuit. This saves ~170k R1CS for a single pairing.
- For the final exponentiation, we completely implement it for BN254 and BLS12-381 using torus-based arithmetic. This allows us to write constraints in Fp6 instead of Fp12. We derive formulas of multiplication, squarings, Frobenius exponentiations following [torus literature](https://www.math.uci.edu/~asilverb/bibliography/ceilidh.pdf). We absorb the compression cost at the easy part stage and deal with -1/1 edge cases with an R1CS-select logic. The cost is almost divided by 3. This was not worth it for BLS12-377 as we use [Karabina cyclotomic square](https://eprint.iacr.org/2010/542.pdf) for the repeated 46 squarings — which is better than torus-squaring for this size.
- For tower fields, we use Karabina and Toom-cook multiplication logic. We use hints (out-circuit computation + in-circuit verification) whenever possible (Inverse, Division, Torus-square...). The dominant cost in the final exponentiation is the exponentiation by the curve seed (constant), which we write efficiently using an optimized addition chain.
- For ECDSA, the bottlneck is 2 scalar multiplication one of which is with the generator point. We use a right-to-left double-and-add method so that we repeatedly double the input point. We assume that the first bit is 1 so that we start the loop with the input point rather than the infinity point. We use affine incomplete doublings and additions and at the end we subtract the input point if the first bit was 0. For the scalar multiplication by the fixed generator, we pre-compute all the doublings and only do additions in-circuit. When we want to deal with edge case, we implemented [Brier-Joye](https://www.iacr.org/archive/ches2006/28/28.pdf) unified addition which works the same for both doubling and addition. 
