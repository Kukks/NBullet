using NBullet;
using NBullet.BouncyCastle;
using NBullet.Secp256k1;
using Org.BouncyCastle.Crypto.Digests;

namespace NBullet.Tests;

public class FiatShamirTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Fact]
    public void TestKeccakFS()
    {
        var fs = new KeccakFiatShamirEngine();
        fs.AddScalar(_group.ScalarFromInt(1));
        fs.AddScalar(_group.ScalarFromInt(2));

        var c1 = fs.GetChallenge(_group);

        // Manually compute expected: Keccak256(1 || 2 || counter=1)
        var digest = new KeccakDigest(256);
        var b1 = ScalarTo32Bytes(_group.ScalarFromInt(1));
        var b2 = ScalarTo32Bytes(_group.ScalarFromInt(2));
        var bCounter1 = ScalarTo32Bytes(_group.ScalarFromInt(1)); // counter

        digest.BlockUpdate(b1, 0, b1.Length);
        digest.BlockUpdate(b2, 0, b2.Length);
        digest.BlockUpdate(bCounter1, 0, bCounter1.Length);

        var hash = new byte[32];
        var clone = new KeccakDigest(digest);
        clone.DoFinal(hash, 0);

        var c2 = _group.ScalarFromBytes(hash);

        Assert.Equal(c1.ToBigInteger(), c2.ToBigInteger());

        // Second round: add more data and get another challenge
        fs.AddScalar(_group.ScalarFromInt(3));
        var c3 = fs.GetChallenge(_group);

        // Manual: state continues from after first Sum, then absorbs 3 || counter=2
        var b3 = ScalarTo32Bytes(_group.ScalarFromInt(3));
        var bCounter2 = ScalarTo32Bytes(_group.ScalarFromInt(2)); // counter

        digest.BlockUpdate(b3, 0, b3.Length);
        digest.BlockUpdate(bCounter2, 0, bCounter2.Length);

        var hash2 = new byte[32];
        var clone2 = new KeccakDigest(digest);
        clone2.DoFinal(hash2, 0);

        var c4 = _group.ScalarFromBytes(hash2);

        Assert.Equal(c3.ToBigInteger(), c4.ToBigInteger());

        // Challenges should be different
        Assert.NotEqual(c1.ToBigInteger(), c3.ToBigInteger());
    }

    [Fact]
    public void TestSha256FS()
    {
        var fs = new Sha256FiatShamirEngine();
        fs.AddScalar(_group.ScalarFromInt(1));
        fs.AddScalar(_group.ScalarFromInt(2));

        var c1 = fs.GetChallenge(_group);

        // Same inputs should produce same challenge (determinism)
        var fs2 = new Sha256FiatShamirEngine();
        fs2.AddScalar(_group.ScalarFromInt(1));
        fs2.AddScalar(_group.ScalarFromInt(2));

        var c2 = fs2.GetChallenge(_group);

        Assert.Equal(c1.ToBigInteger(), c2.ToBigInteger());

        // Second challenge should differ from first
        fs.AddScalar(_group.ScalarFromInt(3));
        var c3 = fs.GetChallenge(_group);

        fs2.AddScalar(_group.ScalarFromInt(3));
        var c4 = fs2.GetChallenge(_group);

        Assert.Equal(c3.ToBigInteger(), c4.ToBigInteger());
        Assert.NotEqual(c1.ToBigInteger(), c3.ToBigInteger());
    }

    [Fact]
    public void TestDifferentEnginesProduceDifferentChallenges()
    {
        var keccak = new KeccakFiatShamirEngine();
        var sha256 = new Sha256FiatShamirEngine();

        keccak.AddScalar(_group.ScalarFromInt(42));
        sha256.AddScalar(_group.ScalarFromInt(42));

        var c1 = keccak.GetChallenge(_group);
        var c2 = sha256.GetChallenge(_group);

        // Different hash functions should produce different challenges
        Assert.NotEqual(c1.ToBigInteger(), c2.ToBigInteger());
    }

    private static byte[] ScalarTo32Bytes(IScalar s)
    {
        var arr = s.ToBytes();
        if (arr.Length >= 32)
            return arr[..32];

        var result = new byte[32];
        Array.Copy(arr, 0, result, 32 - arr.Length, arr.Length);
        return result;
    }
}
