using System.Security.Cryptography;

namespace NBullet;

/// <summary>
/// Fiat-Shamir engine using .NET's built-in SHA-256. Zero external dependencies.
/// Keeps a running transcript of all absorbed data and hashes the full buffer on each challenge.
/// </summary>
public sealed class Sha256FiatShamirEngine : IFiatShamirEngine
{
    private readonly MemoryStream _transcript = new();
    private int _counter;

    public void AddPoint(IPoint p) => Write(p.Serialize());

    public void AddScalar(IScalar s) => Write(ScalarTo32Bytes(s));

    public IScalar GetChallenge(IGroup group)
    {
        _counter++;
        AddScalar(group.ScalarFromInt(_counter));

        var hash = SHA256.HashData(_transcript.ToArray());
        return group.ScalarFromBytes(hash);
    }

    private void Write(byte[] data) => _transcript.Write(data, 0, data.Length);

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
