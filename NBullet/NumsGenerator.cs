using System.Security.Cryptography;

namespace NBullet;

/// <summary>
/// Deterministic NUMS (Nothing Up My Sleeve) point generator for secp256k1.
/// Produces points with unknown discrete log relative to G via hash_to_curve.
/// </summary>
public static class NumsGenerator
{
    /// <summary>
    /// Hash-to-curve: SHA256(input || nonce) interpreted as x-coordinate, lifted to a curve point (even y).
    /// Increments nonce until a valid point is found.
    /// </summary>
    public static IPoint HashToCurve(byte[] input, IGroup group)
    {
        for (int nonce = 0; nonce < 256; nonce++)
        {
            var data = new byte[input.Length + 1];
            Buffer.BlockCopy(input, 0, data, 0, input.Length);
            data[^1] = (byte)nonce;

            var hash = SHA256.HashData(data);

            var compressed = new byte[33];
            compressed[0] = 0x02; // even y
            Buffer.BlockCopy(hash, 0, compressed, 1, 32);

            var point = group.TryParsePoint(compressed);
            if (point != null && !point.IsInfinity)
                return point;
        }

        throw new InvalidOperationException("HashToCurve: exhausted 256 nonce attempts");
    }

    /// <summary>
    /// Standard secondary Pedersen base: H = hash_to_curve(serialize(G)).
    /// Elements-compatible derivation from the standard generator.
    /// </summary>
    public static IPoint StandardH(IGroup group)
    {
        return HashToCurve(group.Generator.Serialize(), group);
    }

    /// <summary>
    /// Application-specific generator: H_A = hash_to_curve(SHA256(tag || domain_data)).
    /// Used for independent asset/commitment bases with domain separation.
    /// </summary>
    public static IPoint ApplicationGenerator(string tag, byte[] domainData, IGroup group)
    {
        var tagBytes = System.Text.Encoding.UTF8.GetBytes(tag);
        var combined = new byte[tagBytes.Length + domainData.Length];
        Buffer.BlockCopy(tagBytes, 0, combined, 0, tagBytes.Length);
        Buffer.BlockCopy(domainData, 0, combined, tagBytes.Length, domainData.Length);

        var hash = SHA256.HashData(combined);
        return HashToCurve(hash, group);
    }

    /// <summary>
    /// Generate a deterministic array of NUMS points for protocol parameters (GVec, HVec).
    /// Each point is derived from ApplicationGenerator(prefix, big-endian index bytes).
    /// </summary>
    public static IPoint[] DeterministicGenerators(string prefix, int count, IGroup group)
    {
        var generators = new IPoint[count];
        for (int i = 0; i < count; i++)
        {
            var indexBytes = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(indexBytes);
            generators[i] = ApplicationGenerator(prefix, indexBytes, group);
        }
        return generators;
    }

    /// <summary>
    /// Create a deterministic ReciprocalPublic with NUMS generators instead of random points.
    /// </summary>
    public static ReciprocalPublic CreateDeterministicReciprocalPublic(
        int nd, int np, IGroup group)
    {
        var g = StandardH(group);
        int totalG = VectorMath.PowerOfTwo(nd);
        int totalH = VectorMath.PowerOfTwo(nd + 1 + 9);

        var gvec = DeterministicGenerators("NBullet.GVec", totalG, group);
        var hvecNums = DeterministicGenerators("NBullet.HVec", totalH - 1, group);
        var hvec = new[] { group.Generator }.Concat(hvecNums).ToArray();

        return new ReciprocalPublic
        {
            G = g,
            GVec = gvec[..nd],
            HVec = hvec[..(nd + 1 + 9)],
            Nd = nd,
            Np = np,
            GVec_ = gvec[nd..],
            HVec_ = hvec[(nd + 1 + 9)..]
        };
    }
}
