using NBullet;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class ConfidentialTransactionTests
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

        var inputRaFactors = new IScalar[N];
        var inputRvFactors = new IScalar[N];
        var outputRaFactors = new IScalar[M];
        var outputRvFactors = new IScalar[M];

        var inputs = new ConfidentialTxInput[N];
        for (int i = 0; i < N; i++)
        {
            inputRaFactors[i] = _group.RandomScalar();
            inputRvFactors[i] = _group.RandomScalar();

            var blindedTag = ConfidentialTransaction.BlindAssetTag(inputAssetGens[i], inputRaFactors[i], _group);
            var valueCom = ConfidentialTransaction.CommitValue(h,
                _group.ScalarFromBigInteger(new System.Numerics.BigInteger(inputValues[i])),
                inputRvFactors[i], G);

            inputs[i] = new ConfidentialTxInput
            {
                ValueCommitment = valueCom,
                BlindedAssetTag = blindedTag
            };
        }

        var outputs = new ConfidentialTxOutput[M];
        for (int j = 0; j < M; j++)
        {
            outputRaFactors[j] = _group.RandomScalar();
            outputRvFactors[j] = _group.RandomScalar();

            var blindedTag = ConfidentialTransaction.BlindAssetTag(outputAssetGens[j], outputRaFactors[j], _group);
            var valueCom = ConfidentialTransaction.CommitValue(h,
                _group.ScalarFromBigInteger(new System.Numerics.BigInteger(outputValues[j])),
                outputRvFactors[j], G);

            outputs[j] = new ConfidentialTxOutput
            {
                ValueCommitment = valueCom,
                BlindedAssetTag = blindedTag
            };
        }

        var excessScalar = _group.ScalarFromInt(0);
        for (int j = 0; j < M; j++)
            excessScalar = excessScalar.Add(outputRvFactors[j]);
        for (int i = 0; i < N; i++)
            excessScalar = excessScalar.Sub(inputRvFactors[i]);
        var excess = G.ScalarMul(excessScalar);

        var witness = new ConfidentialTxWitness
        {
            OutputValues = outputValues,
            OutputValueBlindingFactors = outputRvFactors,
            InputAssetBlindingFactors = inputRaFactors,
            OutputAssetBlindingFactors = outputRaFactors,
            MatchingInputIndices = matchingIndices
        };

        return (inputs, outputs, excess, witness);
    }

    [Fact]
    public void TestSingleInputSingleOutput()
    {
        var assetGen = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            inputValues: new ulong[] { 100 },
            outputValues: new ulong[] { 100 },
            matchingIndices: new int[] { 0 },
            inputAssetGens: new[] { assetGen },
            outputAssetGens: new[] { assetGen }
        );

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = ConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = ConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestOneInputTwoOutputs()
    {
        var assetGen = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            inputValues: new ulong[] { 1000 },
            outputValues: new ulong[] { 600, 400 },
            matchingIndices: new int[] { 0, 0 },
            inputAssetGens: new[] { assetGen },
            outputAssetGens: new[] { assetGen, assetGen }
        );

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = ConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = ConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestZeroValueOutput()
    {
        var assetGen = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            inputValues: new ulong[] { 50 },
            outputValues: new ulong[] { 50, 0 },
            matchingIndices: new int[] { 0, 0 },
            inputAssetGens: new[] { assetGen },
            outputAssetGens: new[] { assetGen, assetGen }
        );

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = ConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = ConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestMaxValueOutput()
    {
        var assetGen = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            inputValues: new ulong[] { ulong.MaxValue },
            outputValues: new ulong[] { ulong.MaxValue },
            matchingIndices: new int[] { 0 },
            inputAssetGens: new[] { assetGen },
            outputAssetGens: new[] { assetGen }
        );

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = ConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = ConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestConservationFailure_MismatchedSums()
    {
        var assetGen = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);
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
                BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(assetGen, inputRa, _group)
            }
        };

        var outputs = new[]
        {
            new ConfidentialTxOutput
            {
                ValueCommitment = ConfidentialTransaction.CommitValue(h,
                    _group.ScalarFromBigInteger(200), outputRv, G),
                BlindedAssetTag = ConfidentialTransaction.BlindAssetTag(assetGen, outputRa, _group)
            }
        };

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

        var proof = ConfidentialTransaction.Prove(inputs, outputs, wrongExcess, witness, MakeFs, _group);
        var err = ConfidentialTransaction.Verify(inputs, outputs, wrongExcess, proof, MakeFs, _group);

        Assert.NotNull(err);
        Assert.Contains("conservation", err!);
    }

    [Fact]
    public void TestTwoInputsTwoOutputs_DifferentAssets()
    {
        var assetBtc = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);
        var assetUsd = NumsGenerator.ApplicationGenerator("USD", new byte[] { 0x02 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            inputValues: new ulong[] { 100, 500 },
            outputValues: new ulong[] { 100, 500 },
            matchingIndices: new int[] { 0, 1 },
            inputAssetGens: new[] { assetBtc, assetUsd },
            outputAssetGens: new[] { assetBtc, assetUsd }
        );

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = ConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = ConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestThreeInputsThreeOutputs()
    {
        var asset = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);

        var (inputs, outputs, excess, witness) = BuildTransaction(
            inputValues: new ulong[] { 100, 200, 300 },
            outputValues: new ulong[] { 150, 250, 200 },
            matchingIndices: new int[] { 0, 1, 2 },
            inputAssetGens: new[] { asset, asset, asset },
            outputAssetGens: new[] { asset, asset, asset }
        );

        IFiatShamirEngine MakeFs() => new Sha256FiatShamirEngine();

        var proof = ConfidentialTransaction.Prove(inputs, outputs, excess, witness, MakeFs, _group);
        var err = ConfidentialTransaction.Verify(inputs, outputs, excess, proof, MakeFs, _group);

        Assert.Null(err);
    }
}
