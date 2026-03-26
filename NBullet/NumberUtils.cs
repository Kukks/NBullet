namespace NBullet;

/// <summary>
/// Numeric utilities for hex decomposition of uint64 values, used in reciprocal range proofs.
/// </summary>
public static class NumberUtils
{
    /// <summary>
    /// Decomposes a uint64 value into 16 hex digits (base-16), least significant first.
    /// </summary>
    public static IScalar[] UInt64Hex(ulong x, IGroup group)
    {
        var resp = new IScalar[16];
        for (int i = 0; i < 16; i++)
        {
            resp[i] = group.ScalarFromInt((int)(x % 16));
            x /= 16;
        }
        return resp;
    }

    /// <summary>
    /// Computes hex digit frequency: result[i] = count of digit i in the input.
    /// </summary>
    public static IScalar[] HexMapping(IScalar[] digits, IGroup group)
    {
        var resp = VectorMath.ZeroVector(group, 16);
        foreach (var d in digits)
        {
            var dint = (int)d.ToBigInteger();
            resp[dint] = resp[dint].Add(group.ScalarFromInt(1));
        }
        return resp;
    }
}
