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
- For pairings (BLS12-377, BN254 and BL12-381) we follow [Housni22](https://eprint.iacr.org/2022/1162). Mainly we write G2 arithmetic in affine coordinates and use [ELM03](https://arxiv.org/pdf/math/0208038.pdf) to optimize the formulas of Double-And-Add. We multiply the line `R0*y+R1*x+R2=0` by `1/(R0*y)` (which is killed later by the final exponentiation) to store only two line coefficient and make the sparse-multiplication even more efficient constraint-wise. Contrary to gnark, we isolate the first two iteration in the Miller loop to avoid squaring and plain multiplication in the full extension. We also isolate the last iteration to save a doubling/addition step as we only need the resulting line and not the resulting point. We also multiply the lines 2-by-2 to exploit sparcity to its fullest.
- For the minimal-pubkey-size variant of BLS signature (or also KZG polynomial commitment), we write a special Miller loop circuit that uses precomputations. In fact, in the ate Miller loop all the doubling, additions are avoided — we precompute all the lines and only evaluate them in the first argument inside the circuit. This saves ~170k R1CS for a single pairing.
- For the final exponentiation, we completely implement it for BN254 and BLS12-381 using torus-based arithmetic. This allows us to write constraints in Fp6 instead of Fp12. We derive formulas of multiplication, squarings, Frobenius following the XTR/Lucas literature. The cost is almost divided by 3.
