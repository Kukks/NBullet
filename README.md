# NBullet

Bulletproofs++ (BP++) zero-knowledge proof library for .NET.

Ported from [distributed-lab/bulletproofs](https://github.com/distributed-lab/bulletproofs) (Go) to C# with a modular, interface-based architecture that allows swapping elliptic curves and hash functions.

> **Warning:** This library has not been audited. Use at your own risk.

## What are Bulletproofs++?

Bulletproofs++ is an advanced zero-knowledge proof protocol that lets you prove statements about committed values without revealing those values. Compared to the original Bulletproofs, BP++ achieves a **2-point efficiency gain** for single 64-bit range proofs (13 curve points vs 16).

This library implements:

| Protocol | Purpose | Key Use Case |
|----------|---------|--------------|
| **WNLA** | Weight Norm Linear Argument | Foundation for the other protocols |
| **Arithmetic Circuits** | Prove arbitrary constraint systems | General-purpose ZK proofs (e.g., `x + y = r` AND `x * y = z`) |
| **Reciprocal Range Proofs** | Prove a value is in `[0, 2^n)` | Confidential transactions, age verification |
| **NUMS Generators** | Deterministic nothing-up-my-sleeve points | Trustless setup for any protocol |
| **Selection Proofs** | Prove one-of-N membership without revealing which | Surjection proofs, anonymous credentials, voting |
| **Batch Verification** | Verify multiple proofs efficiently | High-throughput systems |
| **Confidential Transactions** | Range + surjection + conservation (helper) | Privacy-preserving asset transfers |

## Packages

| Package | Description | Dependencies |
|---------|-------------|--------------|
| **[NBullet](https://www.nuget.org/packages/NBullet/)** | Core protocol logic + interfaces + SHA-256 Fiat-Shamir | None |
| **[NBullet.Secp256k1](https://www.nuget.org/packages/NBullet.Secp256k1/)** | secp256k1 curve adapter (`IGroup`/`IScalar`/`IPoint`) | NBitcoin.Secp256k1 |
| **[NBullet.BouncyCastle](https://www.nuget.org/packages/NBullet.BouncyCastle/)** | Keccak-256 and other BouncyCastle hash adapters | BouncyCastle.Cryptography |

Install what you need:

```bash
# Core + secp256k1 (SHA-256 Fiat-Shamir included in core)
dotnet add package NBullet
dotnet add package NBullet.Secp256k1

# Optional: Keccak-256 support (matches original Go implementation)
dotnet add package NBullet.BouncyCastle
```

## Quick Start

### Range Proof (most common use case)

```csharp
using NBullet;
using NBullet.Secp256k1;

var group = Secp256k1Group.Instance;

// Deterministic NUMS generators — no trusted setup
var pub = NumsGenerator.CreateDeterministicReciprocalPublic(16, 16, group);

// Prover: commit to a value and prove it's in range [0, 2^64)
ulong value = 42;
var x = group.ScalarFromBigInteger(new System.Numerics.BigInteger(value));
var digits = NumberUtils.UInt64Hex(value, group);
var m = NumberUtils.HexMapping(digits, group);
var s = group.RandomScalar();

var priv = new ReciprocalPrivate { X = x, M = m, Digits = digits, S = s };
var commitment = Reciprocal.CommitValue(pub, priv.X, priv.S);

var proof = Reciprocal.ProveRange(pub, new Sha256FiatShamirEngine(), priv, group);
var error = Reciprocal.VerifyRange(pub, commitment, new Sha256FiatShamirEngine(), proof, group);
// error == null means proof is valid
```

### NUMS Generators

Generate deterministic nothing-up-my-sleeve curve points with unknown discrete log:

```csharp
// Standard secondary Pedersen base H = hash_to_curve(serialize(G))
var h = NumsGenerator.StandardH(group);

// Application-specific generators with domain separation
var assetTag = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, group);

// Vector of generators for protocol parameters
var generators = NumsGenerator.DeterministicGenerators("MyProtocol.GVec", 32, group);
```

### Selection Proof (one-of-N membership)

Prove that for each of K groups, exactly one of N elements was selected — without revealing which:

```csharp
// 2 groups, 3 elements each: group 0 selects element 1, group 1 selects element 2
var selections = new[]
{
    new[] { 0, 1, 0 },
    new[] { 0, 0, 1 }
};

var (proof, commitments) = SelectionProof.Prove(2, 3, selections,
    new Sha256FiatShamirEngine(), group);

var error = SelectionProof.Verify(2, 3, commitments, proof,
    new Sha256FiatShamirEngine(), group);
```

### Batch Verification

Verify multiple range proofs faster than checking individually:

```csharp
var items = proofs.Select((p, i) => new BatchVerifier.BatchItem
{
    Public = pub,
    ValueCommitment = commitments[i],
    Proof = p,
    FiatShamir = new Sha256FiatShamirEngine()
}).ToArray();

var error = BatchVerifier.VerifyBatch(items, group);
```

### Confidential Transactions (helper)

The `ConfidentialTransaction` helper combines range proofs, selection proofs, and a conservation check for privacy-preserving asset transfers:

```csharp
// Build inputs/outputs with blinded asset tags and value commitments
var h = NumsGenerator.StandardH(group);
var G = group.Generator;

var inputs = new[] {
    new ConfidentialTxInput {
        ValueCommitment = ConfidentialTransaction.CommitValue(h, inputValueScalar, inputRv, G),
        BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(assetGen, inputRa, group)
    }
};

var outputs = new[] {
    new ConfidentialTxOutput {
        ValueCommitment = ConfidentialTransaction.CommitValue(h, outputValueScalar, outputRv, G),
        BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(assetGen, outputRa, group)
    }
};

var excess = G.ScalarMul(outputRv.Sub(inputRv));

var witness = new ConfidentialTxWitness {
    OutputValues = new ulong[] { outputValue },
    OutputValueBlindingFactors = new[] { outputRv },
    InputAssetBlindingFactors = new[] { inputRa },
    OutputAssetBlindingFactors = new[] { outputRa },
    MatchingInputIndices = new[] { 0 }
};

IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();
var proof = ConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, group);
var error = ConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, group);
```

### Using Keccak-256 (matches Go implementation)

```csharp
using NBullet.BouncyCastle; // requires NBullet.BouncyCastle package

var proof = Reciprocal.ProveRange(pub, new KeccakFiatShamirEngine(), priv, group);
var error = Reciprocal.VerifyRange(pub, commitment, new KeccakFiatShamirEngine(), proof, group);
```

## Architecture

### Modular Design

NBullet is split into three packages so you only pull in the dependencies you need:

```
NBullet (core)                    NBullet.Secp256k1           NBullet.BouncyCastle
  IGroup, IScalar, IPoint           Secp256k1Group              KeccakFiatShamirEngine
  IFiatShamirEngine                 Secp256k1Scalar             BouncyCastleFiatShamirEngine
  Sha256FiatShamirEngine            Secp256k1Point
  Protocol logic (WNLA,             (sealed classes)
  Circuits, Range Proofs,
  Selection, NUMS, Batch)
  VectorMath, NumberUtils
       ^                               ^
       | (no deps)                      | (NBitcoin.Secp256k1)
       +--------------------------------+
```

#### Curve Abstraction (`IGroup`, `IScalar`, `IPoint`)

All protocol logic is written against these interfaces:

```csharp
public interface IGroup
{
    BigInteger Order { get; }
    IPoint Generator { get; }
    IPoint Infinity { get; }
    IScalar ScalarFromInt(int v);
    IScalar ScalarFromBigInteger(BigInteger v);
    IScalar ScalarFromBytes(byte[] bytes);
    IScalar RandomScalar();
    IPoint RandomPoint();
    IScalar Pow(IScalar x, int y);
    IPoint? TryParsePoint(byte[] serialized);
}

public interface IScalar
{
    IScalar Add(IScalar other);
    IScalar Sub(IScalar other);
    IScalar Mul(IScalar other);
    IScalar Inv();
    IScalar Negate();
    byte[] ToBytes();
    // ...
}

public interface IPoint
{
    IPoint Add(IPoint other);
    IPoint ScalarMul(IScalar scalar);
    byte[] Serialize();
    // ...
}
```

The included adapter uses **secp256k1** via `NBitcoin.Secp256k1`. To use a different curve, implement `IGroup`, `IScalar`, and `IPoint` (use `sealed` classes for JIT devirtualization).

#### Hash Abstraction (`IFiatShamirEngine`)

The Fiat-Shamir transcript engine is pluggable:

```csharp
// SHA-256 (built-in, no extra dependencies)
var fs = new Sha256FiatShamirEngine();

// Keccak-256 (requires NBullet.BouncyCastle package, matches original Go implementation)
var fs = new KeccakFiatShamirEngine();

// Any BouncyCastle IDigest (requires NBullet.BouncyCastle package)
var fs = new BouncyCastleFiatShamirEngine(
    new Blake2bDigest(256),
    d => new Blake2bDigest((Blake2bDigest)d)
);
```

### Project Structure

```
NBullet/                             # Core (zero external dependencies)
  IGroup.cs, IScalar.cs, IPoint.cs     Curve abstraction
  IFiatShamirEngine.cs                 Hash abstraction
  Sha256FiatShamirEngine.cs            Built-in SHA-256 Fiat-Shamir engine
  Types.cs                             Proof structures & public parameters
  Wnla.cs                              Weight Norm Linear Argument protocol
  ArithmeticCircuit.cs                  Arithmetic circuit proofs
  Reciprocal.cs                         Reciprocal range proofs
  NumsGenerator.cs                      Deterministic NUMS point generation
  SelectionProof.cs                     One-hot selection (membership) proofs
  BatchVerifier.cs                      Batch verification for multiple proofs
  ConfidentialTransaction.cs            CT helper (range + surjection + conservation)
  VectorMath.cs                         Vector/matrix arithmetic helpers
  NumberUtils.cs                        Hex decomposition utilities

NBullet.Secp256k1/                   # secp256k1 curve adapter
  Secp256k1Group.cs                    IGroup for secp256k1
  Secp256k1Scalar.cs                   IScalar for secp256k1
  Secp256k1Point.cs                    IPoint for secp256k1

NBullet.BouncyCastle/                # BouncyCastle hash adapters
  KeccakFiatShamirEngine.cs            Keccak-256 + generic BouncyCastle IDigest engine

NBullet.Tests/                       # All tests
  WnlaTests.cs                        WNLA proof round-trip
  ArithmeticCircuitTests.cs            Circuit proofs (addition/multiplication, binary range)
  ReciprocalTests.cs                   Reciprocal range proof for uint64
  NumsGeneratorTests.cs                NUMS derivation, determinism, domain separation
  SelectionProofTests.cs               One-hot selection proof round-trips
  BatchVerifierTests.cs                Batch verification (range + confidential)
  ConfidentialTransactionTests.cs      Confidential transaction end-to-end
  FiatShamirTests.cs                   Fiat-Shamir determinism (SHA-256 + Keccak)
  NumberUtilsTests.cs                  Hex conversion
```

### Protocol Overview

```
  Confidential Transaction (helper)
         |
         | combines
         v
  Range Proof (Reciprocal)  +  Selection Proof  +  Conservation Check
         |                          |
         | constructs constraints   | builds one-hot circuit
         v                          v
  Arithmetic Circuit (ProveCircuit / VerifyCircuit)
         |
         | final verification via
         v
  WNLA (ProveWNLA / VerifyWNLA)
         |
         | built on
         v
  IGroup (scalar/point operations on the chosen curve)
         |
         | generators from
         v
  NumsGenerator (deterministic hash_to_curve)
```

**WNLA** is the recursive core: it proves knowledge of vectors `l`, `n` satisfying a commitment `C = v*G + <l, H> + <n, G>` where `v = <c, l> + |n^2|_mu`. Each recursion halves the vector lengths, producing a logarithmic-size proof.

**Arithmetic Circuits** encode constraint systems `Wm * w = wl o wr` (Hadamard product) and `Wl * w + v + al = 0` (linear constraints), then reduce them to a single WNLA instance.

**Reciprocal Range Proofs** decompose a value into hex digits, construct an arithmetic circuit proving the decomposition is valid and each digit is in `[0, 15]`, and produce a compact proof.

**NUMS Generators** produce curve points with provably unknown discrete logs via `hash_to_curve(SHA256(input || nonce))`. Used for trustless setup of Pedersen commitment bases, generator vectors, and application-specific asset tags.

**Selection Proofs** prove that for each of K groups, exactly one of N binary variables is 1 (one-hot selection). This is a general-purpose primitive useful for surjection proofs, anonymous set membership, voting protocols, and credential systems.

**Batch Verification** allows verifying multiple independent proofs faster than checking each one individually, using randomized linear combinations of verification equations.

**Confidential Transactions** is a helper that composes range proofs, selection proofs, and a balance (conservation) check for privacy-preserving asset transfers with blinded amounts and asset tags.

## Differences from the Go Implementation

| Aspect | Go (original) | C# (this library) |
|--------|---------------|-------------------|
| Curve | BN256 (~100-bit security) | secp256k1 (~128-bit security) |
| Architecture | Concrete types, single package | Interface-based, split into adapter packages |
| Hash | Keccak-256 only | Pluggable (SHA-256 built-in, Keccak via adapter) |
| NUMS generators | N/A | Deterministic hash_to_curve for trustless setup |
| Selection proofs | N/A | General one-hot membership proofs |
| Batch verification | N/A | Multi-proof batch verifier |
| Confidential transactions | N/A | Helper combining range + surjection + conservation |
| Cross-compatibility | - | None (different curve = different proofs) |

The core protocol logic (WNLA, circuits, reciprocal) is identical. Switching from BN256 to secp256k1 is an upgrade: BN256 is a pairing-friendly curve with sub-exponential attacks in the target group (~100-bit security), while secp256k1 offers the full ~128-bit DL security. Bulletproofs++ never uses pairings, so BN256's pairing support provides no benefit.

## CI/CD

GitHub Actions automatically builds, tests, and publishes all three NuGet packages when their version in the respective `.csproj` changes on `main`. Add a `NUGET_API_KEY` secret to enable publishing.

## License

MIT - see [LICENSE](LICENSE).

## Credits

- Original Go implementation: [distributed-lab/bulletproofs](https://github.com/distributed-lab/bulletproofs)
- Based on the [Bulletproofs++](https://eprint.iacr.org/2022/510) paper by Liam Eagen and Sanket Kanjalkar.
