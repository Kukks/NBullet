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
        var b3 = ScalarTo32Bytes(_group.ScalarFromInt(1)); // counter

        digest.BlockUpdate(b1, 0, b1.Length);
        digest.BlockUpdate(b2, 0, b2.Length);
        digest.BlockUpdate(b3, 0, b3.Length);

        var hash = new byte[32];
        var clone = new KeccakDigest(digest);
        clone.DoFinal(hash, 0);

        var c2 = _group.ScalarFromBytes(hash);

        Assert.Equal(c1.ToBigInteger(), c2.ToBigInteger());
    }

    [Fact]
    public void TestSha256FS()
    {
        var fs = new Sha256FiatShamirEngine();
        fs.AddScalar(_group.ScalarFromInt(1));
        fs.AddScalar(_group.ScalarFromInt(2));

        var c1 = fs.GetChallenge(_group);

        // Same inputs should produce same challenge
        var fs2 = new Sha256FiatShamirEngine();
        fs2.AddScalar(_group.ScalarFromInt(1));
        fs2.AddScalar(_group.ScalarFromInt(2));

        var c2 = fs2.GetChallenge(_group);

        Assert.Equal(c1.ToBigInteger(), c2.ToBigInteger());
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
