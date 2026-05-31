using NBullet;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class UnifiedConfidentialTransactionTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    private (ConfidentialTxInput[] inputs, ConfidentialTxOutput[] outputs, IPoint excess,
        ConfidentialTxWitness witness) BuildTransaction(
        ulong[] inputValues, ulong[] outputValues,
        int[] matchingIndices, IPoint[] inputAssetGens, IPoint[] outputAssetGens)
    {
        int N = inputValues.Length;
        int M = outputValues.Length;
        var h = NumsGenerator.StandardH(_group);
        var G = _group.Generator;

        var inputRa = new IScalar[N];
        var inputRv = new IScalar[N];
        var outputRa = new IScalar[M];
        var outputRv = new IScalar[M];

        var inputs = new ConfidentialTxInput[N];
        for (int i = 0; i < N; i++)
        {
            inputRa[i] = _group.RandomScalar();
            inputRv[i] = _group.RandomScalar();
            inputs[i] = new ConfidentialTxInput
            {
                ValueCommitment = ConfidentialTransaction.CommitValue(h,
                    _group.ScalarFromBigInteger(new System.Numerics.BigInteger(inputValues[i])),
                    inputRv[i], G),
                BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(inputAssetGens[i], inputRa[i], _group)
            };
        }

        var outputs = new ConfidentialTxOutput[M];
        for (int j = 0; j < M; j++)
        {
            outputRa[j] = _group.RandomScalar();
            outputRv[j] = _group.RandomScalar();
            outputs[j] = new ConfidentialTxOutput
            {
                ValueCommitment = ConfidentialTransaction.CommitValue(h,
                    _group.ScalarFromBigInteger(new System.Numerics.BigInteger(outputValues[j])),
                    outputRv[j], G),
                BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(outputAssetGens[j], outputRa[j], _group)
            };
        }

        var excessScalar = _group.ScalarFromInt(0);
        for (int j = 0; j < M; j++) excessScalar = excessScalar.Add(outputRv[j]);
        for (int i = 0; i < N; i++) excessScalar = excessScalar.Sub(inputRv[i]);
        var excess = G.ScalarMul(excessScalar);

        var witness = new ConfidentialTxWitness
        {
            OutputValues = outputValues,
            OutputValueBlindingFactors = outputRv,
            InputAssetBlindingFactors = inputRa,
            OutputAssetBlindingFactors = outputRa,
            MatchingInputIndices = matchingIndices
        };

        return (inputs, outputs, excess, witness);
    }

    [Fact]
    public void TestUnified_SingleInputSingleOutput()
    {
        var asset = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            new ulong[] { 100 }, new ulong[] { 100 },
            new int[] { 0 },
            new[] { asset }, new[] { asset });

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = UnifiedConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = UnifiedConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestUnified_OneInputThreeOutputs()
    {
        var asset = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            new ulong[] { 1000 }, new ulong[] { 300, 400, 300 },
            new int[] { 0, 0, 0 },
            new[] { asset }, new[] { asset, asset, asset });

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = UnifiedConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = UnifiedConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestUnified_TwoInputsTwoOutputs_DifferentAssets()
    {
        var btc = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);
        var usd = NumsGenerator.ApplicationGenerator("USD", new byte[] { 0x02 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            new ulong[] { 100, 500 }, new ulong[] { 100, 500 },
            new int[] { 0, 1 },
            new[] { btc, usd }, new[] { btc, usd });

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = UnifiedConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = UnifiedConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestUnified_ConservationFailure_MismatchedSums()
    {
        var asset = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);
        var h = NumsGenerator.StandardH(_group);
        var G = _group.Generator;

        var inputRv = _group.RandomScalar();
        var outputRv = _group.RandomScalar();
        var inputRa = _group.RandomScalar();
        var outputRa = _group.RandomScalar();

        var inputs = new[]
        {
            new ConfidentialTxInput
            {
                ValueCommitment = ConfidentialTransaction.CommitValue(h,
                    _group.ScalarFromBigInteger(100), inputRv, G),
                BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(asset, inputRa, _group)
            }
        };

        var outputs = new[]
        {
            new ConfidentialTxOutput
            {
                ValueCommitment = ConfidentialTransaction.CommitValue(h,
                    _group.ScalarFromBigInteger(200), outputRv, G),
                BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(asset, outputRa, _group)
            }
        };

        // Wrong excess: ignores the value mismatch.
        var wrongExcess = G.ScalarMul(outputRv.Sub(inputRv));

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var witness = new ConfidentialTxWitness
        {
            OutputValues = new ulong[] { 200 },
            OutputValueBlindingFactors = new[] { outputRv },
            InputAssetBlindingFactors = new[] { inputRa },
            OutputAssetBlindingFactors = new[] { outputRa },
            MatchingInputIndices = new int[] { 0 }
        };

        var proof = UnifiedConfidentialTransaction.Prove(inputs, outputs, wrongExcess, witness, MakeFs, _group);
        var err = UnifiedConfidentialTransaction.Verify(inputs, outputs, wrongExcess, proof, MakeFs, _group);

        Assert.NotNull(err);
        Assert.Contains("conservation", err!);
    }

    [Fact]
    public void TestUnified_SurjectionMismatch_OutputAssetNotInInputs()
    {
        var btc = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);
        var usd = NumsGenerator.ApplicationGenerator("USD", new byte[] { 0x02 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            new ulong[] { 100 }, new ulong[] { 100 },
            new int[] { 0 },                  // prover claims input 0 matches
            new[] { btc }, new[] { usd });    // but asset types differ

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = UnifiedConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = UnifiedConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.NotNull(err);
        Assert.Contains("asset surjection", err!);
    }
}
