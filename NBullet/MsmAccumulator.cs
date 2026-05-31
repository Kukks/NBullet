namespace NBullet;

/// <summary>
/// Multi-scalar-multiplication accumulator: collects (scalar, point) pairs and
/// computes their sum lazily. Used to batch verification equations across many
/// proofs into a single final point check.
/// </summary>
public sealed class MsmAccumulator
{
    private readonly List<(IScalar Scalar, IPoint Point)> _terms = new();

    public int Count => _terms.Count;

    /// <summary>Append a single (scalar, point) term.</summary>
    public void Add(IScalar scalar, IPoint point)
    {
        _terms.Add((scalar, point));
    }

    /// <summary>Append many (scalar_i, point_i) terms.</summary>
    public void AddMany(IScalar[] scalars, IPoint[] points)
    {
        if (scalars.Length != points.Length)
            throw new ArgumentException("scalars and points length mismatch");
        for (int i = 0; i < scalars.Length; i++)
            _terms.Add((scalars[i], points[i]));
    }

    /// <summary>Append (outerWeight * innerScalar, point). Used when batching multiple proofs.</summary>
    public void AddWeighted(IScalar outerWeight, IScalar innerScalar, IPoint point)
    {
        _terms.Add((outerWeight.Mul(innerScalar), point));
    }

    /// <summary>Append (outerWeight * inner_i, point_i) for each i.</summary>
    public void AddManyWeighted(IScalar outerWeight, IScalar[] innerScalars, IPoint[] points)
    {
        if (innerScalars.Length != points.Length)
            throw new ArgumentException("scalars and points length mismatch");
        for (int i = 0; i < innerScalars.Length; i++)
            _terms.Add((outerWeight.Mul(innerScalars[i]), points[i]));
    }

    /// <summary>Compute the sum of all accumulated terms. Returns infinity if empty.</summary>
    public IPoint Sum(IGroup group)
    {
        var acc = group.Infinity;
        foreach (var (s, p) in _terms)
            acc = acc.Add(p.ScalarMul(s));
        return acc;
    }
}
