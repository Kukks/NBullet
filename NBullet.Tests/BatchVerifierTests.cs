using NBullet;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class BatchVerifierTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    private (ReciprocalPublic pub, IPoint vCom, ReciprocalProof proof) MakeRangeProof(ulong value)
    {
        var pub = NumsGenerator.CreateDeterministicReciprocalPublic(16, 16, _group);
        var x = _group.ScalarFromBigInteger(new System.Numerics.BigInteger(value));
        var digits = NumberUtils.UInt64Hex(value, _group);
        var m = NumberUtils.HexMapping(digits, _group);
        var s = _group.RandomScalar();

        var priv = new ReciprocalPrivate { X = x, M = m, Digits = digits, S = s };
        var vCom = Reciprocal.CommitValue(pub, priv.X, priv.S);
        var proof = Reciprocal.ProveRange(pub, new Sha256FiatShamirEngine(), priv, _group);

        return (pub, vCom, proof);
    }

    [Fact]
    public void TestBatchVerify_SingleProof()
    {
        var (pub, vCom, proof) = MakeRangeProof(42);

        var items = new[]
        {
            new BatchVerifier.BatchItem
            {
                Public = pub,
                ValueCommitment = vCom,
                Proof = proof,
                FiatShamir = new Sha256FiatShamirEngine()
            }
        };

        var err = BatchVerifier.VerifyBatch(items, _group);
        Assert.Null(err);
    }

    [Fact]
    public void TestBatchVerify_MultipleProofs()
    {
        var values = new ulong[] { 0, 42, 1000, 999999, ulong.MaxValue };
        var items = new BatchVerifier.BatchItem[values.Length];

        for (int i = 0; i < values.Length; i++)
        {
            var (pub, vCom, proof) = MakeRangeProof(values[i]);
            items[i] = new BatchVerifier.BatchItem
            {
                Public = pub,
                ValueCommitment = vCom,
                Proof = proof,
                FiatShamir = new Sha256FiatShamirEngine()
            };
        }

        var err = BatchVerifier.VerifyBatch(items, _group);
        Assert.Null(err);
    }

    [Fact]
    public void TestBatchVerify_OneBadProof()
    {
        var (pub1, vCom1, proof1) = MakeRangeProof(100);
        var (pub2, vCom2, proof2) = MakeRangeProof(200);

        var wrongCom = Reciprocal.CommitValue(pub2,
            _group.ScalarFromBigInteger(999), _group.RandomScalar());

        var items = new[]
        {
            new BatchVerifier.BatchItem
            {
                Public = pub1, ValueCommitment = vCom1, Proof = proof1,
                FiatShamir = new Sha256FiatShamirEngine()
            },
            new BatchVerifier.BatchItem
            {
                Public = pub2, ValueCommitment = wrongCom, Proof = proof2,
                FiatShamir = new Sha256FiatShamirEngine()
            }
        };

        var err = BatchVerifier.VerifyBatch(items, _group);
        Assert.NotNull(err);
        Assert.Contains("proof 1", err!);
    }

    [Fact]
    public void TestBatchVerify_Empty()
    {
        var err = BatchVerifier.VerifyBatch(Array.Empty<BatchVerifier.BatchItem>(), _group);
        Assert.Null(err);
    }

    [Fact]
    public void TestBatchVerify_TenProofs()
    {
        var rng = new Random(42);
        var items = new BatchVerifier.BatchItem[10];

        for (int i = 0; i < 10; i++)
        {
            var value = (ulong)rng.NextInt64(0, long.MaxValue);
            var (pub, vCom, proof) = MakeRangeProof(value);
            items[i] = new BatchVerifier.BatchItem
            {
                Public = pub, ValueCommitment = vCom, Proof = proof,
                FiatShamir = new Sha256FiatShamirEngine()
            };
        }

        var err = BatchVerifier.VerifyBatch(items, _group);
        Assert.Null(err);
    }

    [Fact]
    public void TestBatchVerifyConfidential_MultipleTxs()
    {
        var asset = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);
        var h = NumsGenerator.StandardH(_group);
        var G = _group.Generator;

        var batchItems = new BatchVerifier.ConfidentialBatchItem[2];

        for (int t = 0; t < 2; t++)
        {
            ulong inputVal = (ulong)(100 + t * 50);
            ulong outputVal = inputVal;

            var inputRv = _group.RandomScalar();
            var outputRv = _group.RandomScalar();
            var inputRa = _group.RandomScalar();
            var outputRa = _group.RandomScalar();

            var inputs = new[]
            {
                new ConfidentialTxInput
                {
                    ValueCommitment = ConfidentialTransaction.CommitValue(h,
                        _group.ScalarFromBigInteger(new System.Numerics.BigInteger(inputVal)), inputRv, G),
                    BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(asset, inputRa, _group)
                }
            };

            var outputs = new[]
            {
                new ConfidentialTxOutput
                {
                    ValueCommitment = ConfidentialTransaction.CommitValue(h,
                        _group.ScalarFromBigInteger(new System.Numerics.BigInteger(outputVal)), outputRv, G),
                    BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(asset, outputRa, _group)
                }
            };

            var excess = G.ScalarMul(outputRv.Sub(inputRv));

            var witness = new ConfidentialTxWitness
            {
                OutputValues = new[] { outputVal },
                OutputValueBlindingFactors = new[] { outputRv },
                InputAssetBlindingFactors = new[] { inputRa },
                OutputAssetBlindingFactors = new[] { outputRa },
                MatchingInputIndices = new[] { 0 }
            };

            IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

            var proof = ConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);

            batchItems[t] = new BatchVerifier.ConfidentialBatchItem
            {
                Inputs = inputs,
                Outputs = outputs,
                Excess = excess,
                Proof = proof,
                MakeFs = MakeFs
            };
        }

        var err = BatchVerifier.VerifyBatchConfidential(batchItems, _group);
        Assert.Null(err);
    }
}
