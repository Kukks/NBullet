using NBullet;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class AssetSurjectionTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    private (IPoint[] inputTags, IPoint outputTag, int trueIndex, IScalar d) BuildScenario(
        int N, int trueIndex)
    {
        // All N inputs share the same underlying asset H so any one can be the source.
        var H = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);
        var G = _group.Generator;

        var inputBlindings = new IScalar[N];
        var inputTags = new IPoint[N];
        for (int i = 0; i < N; i++)
        {
            inputBlindings[i] = _group.RandomScalar();
            inputTags[i] = H.Add(G.ScalarMul(inputBlindings[i]));
        }

        var outputBlinding = _group.RandomScalar();
        var outputTag = H.Add(G.ScalarMul(outputBlinding));

        var d = outputBlinding.Sub(inputBlindings[trueIndex]);

        return (inputTags, outputTag, trueIndex, d);
    }

    [Fact]
    public void TestSurjection_TrueIndexAcceptsAllPositions()
    {
        for (int trueIdx = 0; trueIdx < 5; trueIdx++)
        {
            var (inputs, output, k, d) = BuildScenario(5, trueIdx);

            var fs = new Sha256FiatShamirEngine();
            var proof = AssetSurjection.Prove(inputs, output, k, d, fs, _group);

            var verifyFs = new Sha256FiatShamirEngine();
            var err = AssetSurjection.Verify(inputs, output, proof, verifyFs, _group);
            Assert.Null(err);
        }
    }

    [Fact]
    public void TestSurjection_WrongDifferenceRejects()
    {
        var (inputs, output, k, _) = BuildScenario(3, 1);
        var wrongD = _group.RandomScalar();

        var fs = new Sha256FiatShamirEngine();
        var proof = AssetSurjection.Prove(inputs, output, k, wrongD, fs, _group);

        var verifyFs = new Sha256FiatShamirEngine();
        var err = AssetSurjection.Verify(inputs, output, proof, verifyFs, _group);
        Assert.NotNull(err);
    }

    [Fact]
    public void TestSurjection_OutputAssetNotInInputsRejects()
    {
        // Inputs all use BTC; output uses USD. No valid d satisfies the relation
        // for any input — an honest prover cannot succeed.
        var btc = NumsGenerator.ApplicationGenerator("BTC", new byte[] { 0x01 }, _group);
        var usd = NumsGenerator.ApplicationGenerator("USD", new byte[] { 0x02 }, _group);
        var G = _group.Generator;

        var inputBlindings = new IScalar[3];
        var inputTags = new IPoint[3];
        for (int i = 0; i < 3; i++)
        {
            inputBlindings[i] = _group.RandomScalar();
            inputTags[i] = btc.Add(G.ScalarMul(inputBlindings[i]));
        }

        var outputBlinding = _group.RandomScalar();
        var outputTag = usd.Add(G.ScalarMul(outputBlinding));

        // Prover lies and supplies a d that matches input 0 by raw blinding diff,
        // but outputTag - inputTags[0] is NOT a scalar multiple of G alone.
        var fakeD = outputBlinding.Sub(inputBlindings[0]);

        var fs = new Sha256FiatShamirEngine();
        var proof = AssetSurjection.Prove(inputTags, outputTag, 0, fakeD, fs, _group);

        var verifyFs = new Sha256FiatShamirEngine();
        var err = AssetSurjection.Verify(inputTags, outputTag, proof, verifyFs, _group);
        Assert.NotNull(err);
    }

    [Fact]
    public void TestSurjection_TamperedChallengeRejects()
    {
        var (inputs, output, k, d) = BuildScenario(3, 0);

        var fs = new Sha256FiatShamirEngine();
        var proof = AssetSurjection.Prove(inputs, output, k, d, fs, _group);

        var tampered = new AssetSurjectionProof
        {
            Challenges = (IScalar[])proof.Challenges.Clone(),
            Responses = proof.Responses
        };
        tampered.Challenges[1] = tampered.Challenges[1].Add(_group.ScalarFromInt(1));

        var verifyFs = new Sha256FiatShamirEngine();
        var err = AssetSurjection.Verify(inputs, output, tampered, verifyFs, _group);
        Assert.NotNull(err);
    }

    [Fact]
    public void TestSurjection_TamperedResponseRejects()
    {
        var (inputs, output, k, d) = BuildScenario(3, 2);

        var fs = new Sha256FiatShamirEngine();
        var proof = AssetSurjection.Prove(inputs, output, k, d, fs, _group);

        var tampered = new AssetSurjectionProof
        {
            Challenges = proof.Challenges,
            Responses = (IScalar[])proof.Responses.Clone()
        };
        tampered.Responses[0] = tampered.Responses[0].Add(_group.ScalarFromInt(1));

        var verifyFs = new Sha256FiatShamirEngine();
        var err = AssetSurjection.Verify(inputs, output, tampered, verifyFs, _group);
        Assert.NotNull(err);
    }

    [Fact]
    public void TestSurjection_SingleInput()
    {
        var (inputs, output, k, d) = BuildScenario(1, 0);

        var fs = new Sha256FiatShamirEngine();
        var proof = AssetSurjection.Prove(inputs, output, k, d, fs, _group);

        var verifyFs = new Sha256FiatShamirEngine();
        var err = AssetSurjection.Verify(inputs, output, proof, verifyFs, _group);
        Assert.Null(err);
    }
}
