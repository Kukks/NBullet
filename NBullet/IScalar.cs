using System.Numerics;

namespace NBullet;

/// <summary>
/// Represents a scalar element in a finite field (mod group order).
/// Implementations should be sealed for JIT devirtualization.
/// </summary>
public interface IScalar
{
    IScalar Add(IScalar other);
    IScalar Sub(IScalar other);
    IScalar Mul(IScalar other);
    IScalar Inv();
    IScalar Negate();
    bool IsZero { get; }
    byte[] ToBytes();
    BigInteger ToBigInteger();
}
