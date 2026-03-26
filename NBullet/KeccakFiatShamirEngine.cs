using Org.BouncyCastle.Crypto.Digests;

namespace NBullet;

/// <summary>
/// Fiat-Shamir engine using Keccak-256, matching the Go implementation.
/// Absorbs points and scalars into a running hash state, produces challenges.
/// </summary>
public sealed class KeccakFiatShamirEngine : IFiatShamirEngine
{
    private readonly KeccakDigest _digest = new(256);
    private int _counter;

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

        // Squeeze: get the current hash state without finalizing
        // Clone the digest to preserve state (like Go's keccak.Sum which doesn't finalize)
        var clone = new KeccakDigest(_digest);
        var hash = new byte[32];
        clone.DoFinal(hash, 0);

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
