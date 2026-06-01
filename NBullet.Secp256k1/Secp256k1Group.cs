using System.Numerics;
using System.Security.Cryptography;
using NBitcoin.Secp256k1;

namespace NBullet.Secp256k1;

/// <summary>
/// IGroup implementation for the secp256k1 curve.
/// Provides scalar/point factory methods and the curve generator.
/// </summary>
public sealed class Secp256k1Group : IGroup
{
    public static readonly Secp256k1Group Instance = new();

    private static readonly BigInteger Secp256k1Order =
        BigInteger.Parse("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            System.Globalization.NumberStyles.HexNumber);

    public BigInteger Order => Secp256k1Order;

    public IPoint Generator =>
        new Secp256k1Point(EC.G);

    public IPoint Infinity =>
        new Secp256k1Point(GEJ.Infinity);

    public IScalar ScalarFromInt(int v)
    {
        if (v >= 0)
            return new Secp256k1Scalar(new Scalar((uint)v));

        // Negative: compute order - |v|
        return new Secp256k1Scalar(new Scalar((uint)(-v)).Negate());
    }

    public IScalar ScalarFromBigInteger(BigInteger v)
    {
        // Reduce mod order, handling negatives
        v = ((v % Secp256k1Order) + Secp256k1Order) % Secp256k1Order;
        var bytes = BigIntegerTo32Bytes(v);
        return new Secp256k1Scalar(new Scalar(bytes));
    }

    public IScalar ScalarFromBytes(byte[] bytes)
    {
        if (bytes.Length < 32)
        {
            var padded = new byte[32];
            Array.Copy(bytes, 0, padded, 32 - bytes.Length, bytes.Length);
            return new Secp256k1Scalar(new Scalar(padded));
        }
        return new Secp256k1Scalar(new Scalar(bytes.AsSpan(0, 32)));
    }

    public IScalar RandomScalar()
    {
        Span<byte> buf = stackalloc byte[32];
        Scalar s;
        do
        {
            RandomNumberGenerator.Fill(buf);
            s = new Scalar(buf, out int overflow);
            if (overflow != 0 || s.IsZero) continue;
            break;
        } while (true);
        return new Secp256k1Scalar(s);
    }

    public IPoint RandomPoint()
    {
        var s = (Secp256k1Scalar)RandomScalar();
        return new Secp256k1Point(EC.G * s.Value);
    }

    public IScalar Pow(IScalar x, int y)
    {
        if (y == 0)
            return new Secp256k1Scalar(Scalar.One);

        var baseScalar = (Secp256k1Scalar)x;
        if (y < 0)
        {
            baseScalar = (Secp256k1Scalar)baseScalar.Inv();
            y = -y;
        }

        // Binary exponentiation
        var result = Scalar.One;
        var b = baseScalar.Value;
        while (y > 0)
        {
            if ((y & 1) == 1)
                result = result * b;
            b = b * b;
            y >>= 1;
        }
        return new Secp256k1Scalar(result);
    }

    public IPoint? TryParsePoint(byte[] serialized)
    {
        if (GE.TryParse(serialized, out GE ge))
            return new Secp256k1Point(ge);
        return null;
    }

    private static byte[] BigIntegerTo32Bytes(BigInteger v)
    {
        // BigInteger.ToByteArray() is little-endian and signed.
        // We need big-endian, unsigned, 32 bytes.
        var leBytes = v.ToByteArray(isUnsigned: true, isBigEndian: false);
        var result = new byte[32];
        var len = Math.Min(leBytes.Length, 32);
        for (int i = 0; i < len; i++)
            result[31 - i] = leBytes[i];
        return result;
    }
}
