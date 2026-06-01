using NBullet;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class NumsGeneratorTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Fact]
    public void TestHashToCurve_Deterministic()
    {
        var input = new byte[] { 0x01, 0x02, 0x03 };
        var point1 = NumsGenerator.HashToCurve(input, _group);
        var point2 = NumsGenerator.HashToCurve(input, _group);

        Assert.True(point1.Eq(point2));
        Assert.False(point1.IsInfinity);
    }

    [Fact]
    public void TestHashToCurve_DifferentInputsDifferentPoints()
    {
        var p1 = NumsGenerator.HashToCurve(new byte[] { 0x01 }, _group);
        var p2 = NumsGenerator.HashToCurve(new byte[] { 0x02 }, _group);

        Assert.False(p1.Eq(p2));
    }

    [Fact]
    public void TestStandardH_Deterministic()
    {
        var h1 = NumsGenerator.StandardH(_group);
        var h2 = NumsGenerator.StandardH(_group);

        Assert.True(h1.Eq(h2));
        Assert.False(h1.IsInfinity);
        Assert.False(h1.Eq(_group.Generator));
    }

    [Fact]
    public void TestStandardH_MatchesManualDerivation()
    {
        var gSerialized = _group.Generator.Serialize();
        var hManual = NumsGenerator.HashToCurve(gSerialized, _group);
        var hStandard = NumsGenerator.StandardH(_group);

        Assert.True(hManual.Eq(hStandard));
    }

    [Fact]
    public void TestApplicationGenerator_DomainSeparation()
    {
        var data = new byte[] { 0xaa, 0xbb, 0xcc };
        var g1 = NumsGenerator.ApplicationGenerator("asset_a", data, _group);
        var g2 = NumsGenerator.ApplicationGenerator("asset_b", data, _group);

        Assert.False(g1.Eq(g2));
        Assert.False(g1.IsInfinity);
        Assert.False(g2.IsInfinity);
    }

    [Fact]
    public void TestApplicationGenerator_DifferentDomainData()
    {
        var g1 = NumsGenerator.ApplicationGenerator("asset", new byte[] { 0x01 }, _group);
        var g2 = NumsGenerator.ApplicationGenerator("asset", new byte[] { 0x02 }, _group);

        Assert.False(g1.Eq(g2));
    }

    [Fact]
    public void TestApplicationGenerator_Deterministic()
    {
        var data = new byte[32];
        new Random(42).NextBytes(data);

        var g1 = NumsGenerator.ApplicationGenerator("test_tag", data, _group);
        var g2 = NumsGenerator.ApplicationGenerator("test_tag", data, _group);

        Assert.True(g1.Eq(g2));
    }

    [Fact]
    public void TestDeterministicGenerators_CorrectCount()
    {
        var gens = NumsGenerator.DeterministicGenerators("test", 10, _group);
        Assert.Equal(10, gens.Length);
    }

    [Fact]
    public void TestDeterministicGenerators_AllDistinct()
    {
        var gens = NumsGenerator.DeterministicGenerators("test", 20, _group);

        for (int i = 0; i < gens.Length; i++)
        {
            Assert.False(gens[i].IsInfinity);
            for (int j = i + 1; j < gens.Length; j++)
                Assert.False(gens[i].Eq(gens[j]), $"generators {i} and {j} are equal");
        }
    }

    [Fact]
    public void TestDeterministicGenerators_Reproducible()
    {
        var gens1 = NumsGenerator.DeterministicGenerators("prefix", 5, _group);
        var gens2 = NumsGenerator.DeterministicGenerators("prefix", 5, _group);

        for (int i = 0; i < 5; i++)
            Assert.True(gens1[i].Eq(gens2[i]));
    }

    [Fact]
    public void TestTryParsePoint_ValidCompressed()
    {
        var g = _group.Generator;
        var serialized = g.Serialize();
        var parsed = _group.TryParsePoint(serialized);

        Assert.NotNull(parsed);
        Assert.True(g.Eq(parsed));
    }

    [Fact]
    public void TestTryParsePoint_InvalidBytes()
    {
        var invalid = new byte[33];
        invalid[0] = 0x02;
        for (int i = 1; i < 33; i++) invalid[i] = 0xFF;

        var result = _group.TryParsePoint(invalid);
        // May or may not parse depending on x-coordinate validity
    }

    [Fact]
    public void TestTryParsePoint_RandomPoints()
    {
        for (int i = 0; i < 10; i++)
        {
            var p = _group.RandomPoint();
            var serialized = p.Serialize();
            var parsed = _group.TryParsePoint(serialized);

            Assert.NotNull(parsed);
            Assert.True(p.Eq(parsed!));
        }
    }

    [Fact]
    public void TestCreateDeterministicReciprocalPublic()
    {
        var pub = NumsGenerator.CreateDeterministicReciprocalPublic(16, 16, _group);

        Assert.Equal(16, pub.Nd);
        Assert.Equal(16, pub.Np);
        Assert.Equal(16, pub.GVec.Length);
        Assert.Equal(26, pub.HVec.Length); // 16 + 1 + 9

        Assert.False(pub.G.IsInfinity);
        Assert.False(pub.G.Eq(_group.Generator));
    }

    [Fact]
    public void TestDeterministicReciprocalPublic_ProveAndVerify()
    {
        var pub = NumsGenerator.CreateDeterministicReciprocalPublic(16, 16, _group);

        ulong value = 42;
        var x = _group.ScalarFromBigInteger(new System.Numerics.BigInteger(value));
        var digits = NumberUtils.UInt64Hex(value, _group);
        var m = NumberUtils.HexMapping(digits, _group);
        var s = _group.RandomScalar();

        var priv = new ReciprocalPrivate { X = x, M = m, Digits = digits, S = s };
        var vCom = Reciprocal.CommitValue(pub, priv.X, priv.S);

        var proof = Reciprocal.ProveRange(pub, new Sha256FiatShamirEngine(), priv, _group);
        var err = Reciprocal.VerifyRange(pub, vCom, new Sha256FiatShamirEngine(), proof, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestHashToCurve_EmptyInput()
    {
        var point = NumsGenerator.HashToCurve(Array.Empty<byte>(), _group);
        Assert.False(point.IsInfinity);
    }

    [Fact]
    public void TestHashToCurve_LargeInput()
    {
        var input = new byte[1000];
        new Random(123).NextBytes(input);

        var point = NumsGenerator.HashToCurve(input, _group);
        Assert.False(point.IsInfinity);
    }
}
