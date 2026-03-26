using NBitcoin.Secp256k1;

namespace NBullet.Secp256k1;

/// <summary>
/// Sealed IPoint implementation wrapping NBitcoin.Secp256k1 GEJ (Jacobian point).
/// Stores points in Jacobian form for efficient chained arithmetic,
/// converts to affine (GE) only for serialization/equality.
/// </summary>
public sealed class Secp256k1Point : IPoint
{
    internal readonly GEJ Gej;

    internal Secp256k1Point(in GEJ gej) => Gej = gej;
    internal Secp256k1Point(in GE ge) => Gej = ge.ToGroupElementJacobian();

    public IPoint Add(IPoint other)
    {
        var o = ((Secp256k1Point)other);
        if (Gej.IsInfinity) return other;
        if (o.Gej.IsInfinity) return this;
        return new Secp256k1Point(Gej.AddVariable(o.ToAffine()));
    }

    public IPoint ScalarMul(IScalar scalar)
    {
        var s = ((Secp256k1Scalar)scalar).Value;
        if (s.IsZero) return new Secp256k1Point(GEJ.Infinity);
        // Use GE * Scalar operator for point scalar multiplication
        var ge = ToAffine();
        return new Secp256k1Point(ge * s);
    }

    public byte[] Serialize()
    {
        if (Gej.IsInfinity)
            return new byte[33]; // 33 zero bytes for infinity

        var ge = ToAffine();
        var bytes = new byte[33];
        // Compressed format: 0x02/0x03 prefix + 32 bytes x-coordinate
        var (x, y, _) = ge;
        var xn = x.NormalizeVariable();
        var yn = y.NormalizeVariable();
        xn.WriteToSpan(bytes.AsSpan(1));
        bytes[0] = yn.IsOdd ? (byte)0x03 : (byte)0x02;
        return bytes;
    }

    public bool IsInfinity => Gej.IsInfinity;

    public bool Eq(IPoint other)
    {
        var o = (Secp256k1Point)other;
        if (IsInfinity && o.IsInfinity) return true;
        if (IsInfinity || o.IsInfinity) return false;
        var a = Serialize();
        var b = o.Serialize();
        return a.AsSpan().SequenceEqual(b);
    }

    internal GE ToAffine() => Gej.IsInfinity ? GE.Infinity : Gej.ToGroupElementVariable();

    public override bool Equals(object? obj) => obj is Secp256k1Point other && Eq(other);
    public override int GetHashCode() => Serialize().Aggregate(17, (h, b) => h * 31 + b);
}
