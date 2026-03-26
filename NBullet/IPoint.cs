namespace NBullet;

/// <summary>
/// Represents a point on an elliptic curve.
/// Implementations should be sealed for JIT devirtualization.
/// </summary>
public interface IPoint
{
    IPoint Add(IPoint other);
    IPoint ScalarMul(IScalar scalar);
    byte[] Serialize();
    bool IsInfinity { get; }
    bool Eq(IPoint other);
}
