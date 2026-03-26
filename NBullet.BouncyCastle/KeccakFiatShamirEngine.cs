using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace NBullet.BouncyCastle;

/// <summary>
/// Fiat-Shamir engine backed by any BouncyCastle IDigest.
/// Absorbs points and scalars into a running hash state; squeezes challenges
/// by cloning the state (so the transcript continues absorbing after each challenge).
/// </summary>
public sealed class BouncyCastleFiatShamirEngine : IFiatShamirEngine
{
    private readonly IDigest _digest;
    private readonly Func<IDigest, IDigest> _cloner;
    private int _counter;

    /// <param name="digest">The digest instance to use (e.g. KeccakDigest, Sha256Digest).</param>
    /// <param name="cloner">A function that creates a snapshot copy of the digest state.</param>
    public BouncyCastleFiatShamirEngine(IDigest digest, Func<IDigest, IDigest> cloner)
    {
        _digest = digest;
        _cloner = cloner;
    }

    /// <summary>Creates a Keccak-256 backed engine (matches the original Go implementation).</summary>
    public static BouncyCastleFiatShamirEngine CreateKeccak() =>
        new(new KeccakDigest(256), d => new KeccakDigest((KeccakDigest)d));

    /// <summary>Creates a SHA-256 backed engine using BouncyCastle's SHA-256.</summary>
    public static BouncyCastleFiatShamirEngine CreateSha256() =>
        new(new Sha256Digest(), d => new Sha256Digest((Sha256Digest)d));

    public void AddPoint(IPoint p)
    {
        var bytes = p.Serialize();
        _digest.BlockUpdate(bytes, 0, bytes.Length);
    }

    public void AddScalar(IScalar s)
    {
        var bytes = ScalarTo32Bytes(s);
        _digest.BlockUpdate(bytes, 0, bytes.Length);
    }

    public IScalar GetChallenge(IGroup group)
    {
        _counter++;
        AddScalar(group.ScalarFromInt(_counter));

        var clone = _cloner(_digest);
        var hash = new byte[_digest.GetDigestSize()];
        clone.DoFinal(hash, 0);

        if (hash.Length > 32)
            hash = hash[..32];
        else if (hash.Length < 32)
        {
            var padded = new byte[32];
            Array.Copy(hash, 0, padded, 32 - hash.Length, hash.Length);
            hash = padded;
        }

        return group.ScalarFromBytes(hash);
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

/// <summary>
/// Convenience alias: Keccak-256 Fiat-Shamir engine matching the original Go implementation.
/// </summary>
public sealed class KeccakFiatShamirEngine : IFiatShamirEngine
{
    private readonly BouncyCastleFiatShamirEngine _inner = BouncyCastleFiatShamirEngine.CreateKeccak();

    public void AddPoint(IPoint p) => _inner.AddPoint(p);
    public void AddScalar(IScalar s) => _inner.AddScalar(s);
    public IScalar GetChallenge(IGroup group) => _inner.GetChallenge(group);
}
