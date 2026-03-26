using System.Numerics;
using NBitcoin.Secp256k1;

namespace NBullet.Secp256k1;

/// <summary>
/// Sealed IScalar implementation wrapping NBitcoin.Secp256k1.Scalar.
/// Sealed enables JIT devirtualization for interface calls.
/// </summary>
public sealed class Secp256k1Scalar : IScalar
{
    internal readonly Scalar Value;

    internal Secp256k1Scalar(in Scalar value) => Value = value;

    public IScalar Add(IScalar other) =>
        new Secp256k1Scalar(Value.Add(((Secp256k1Scalar)other).Value));

    public IScalar Sub(IScalar other)
    {
        var neg = ((Secp256k1Scalar)other).Value.Negate();
        return new Secp256k1Scalar(Value.Add(neg));
    }

    public IScalar Mul(IScalar other) =>
        new Secp256k1Scalar(Value * ((Secp256k1Scalar)other).Value);

    public IScalar Inv() => new Secp256k1Scalar(Value.Inverse());

    public IScalar Negate() => new Secp256k1Scalar(Value.Negate());

    public bool IsZero => Value.IsZero;

    public byte[] ToBytes()
    {
        var bytes = new byte[32];
        Value.WriteToSpan(bytes);
        return bytes;
    }

    public BigInteger ToBigInteger()
    {
        var bytes = ToBytes();
        // Scalar.WriteToSpan writes big-endian. BigInteger expects little-endian unsigned.
        var leBytes = new byte[33]; // extra zero byte for unsigned
        for (int i = 0; i < 32; i++)
            leBytes[i] = bytes[31 - i];
        return new BigInteger(leBytes);
    }

    public override bool Equals(object? obj) =>
        obj is Secp256k1Scalar other && Value.Equals(other.Value);

    public override int GetHashCode() => Value.GetHashCode();
}
