using System.Numerics;

namespace NBullet;

/// <summary>
/// Factory and context for a prime-order elliptic curve group.
/// Provides scalar/point creation, generator, and the group order.
/// </summary>
public interface IGroup
{
    /// <summary>The group order (number of points on the curve).</summary>
    BigInteger Order { get; }

    /// <summary>The standard generator point G.</summary>
    IPoint Generator { get; }

    /// <summary>The identity element (point at infinity).</summary>
    IPoint Infinity { get; }

    /// <summary>Create a scalar from an integer (mod order).</summary>
    IScalar ScalarFromInt(int v);

    /// <summary>Create a scalar from a BigInteger (mod order).</summary>
    IScalar ScalarFromBigInteger(BigInteger v);

    /// <summary>Create a scalar from raw bytes (mod order).</summary>
    IScalar ScalarFromBytes(byte[] bytes);

    /// <summary>Generate a cryptographically random scalar.</summary>
    IScalar RandomScalar();

    /// <summary>Generate a random point (random scalar * G).</summary>
    IPoint RandomPoint();

    /// <summary>Raise a scalar to an integer power (mod order).</summary>
    IScalar Pow(IScalar x, int y);

    /// <summary>Try to parse a point from its serialized (compressed) form. Returns null if invalid.</summary>
    IPoint? TryParsePoint(byte[] serialized);
}
