namespace NBullet;

/// <summary>
/// Vector and matrix operations over IScalar and IPoint, ported from Go's math_vectors.go and math_matrix.go.
/// All scalar operations are performed mod group order via the IScalar interface.
/// </summary>
public static class VectorMath
{
    // ─── Scalar vector creation ───

    public static IScalar[] ZeroVector(IGroup group, int n)
    {
        var res = new IScalar[n];
        for (int i = 0; i < n; i++)
            res[i] = group.ScalarFromInt(0);
        return res;
    }

    public static IScalar[] OneVector(IGroup group, int n)
    {
        var res = new IScalar[n];
        for (int i = 0; i < n; i++)
            res[i] = group.ScalarFromInt(1);
        return res;
    }

    // ─── Scalar vector arithmetic ───

    public static IScalar[] VectorAdd(IScalar[] a, IScalar[] b, IGroup group)
    {
        a = PadVector(a, b.Length, group);
        b = PadVector(b, a.Length, group);
        var res = new IScalar[a.Length];
        for (int i = 0; i < res.Length; i++)
            res[i] = a[i].Add(b[i]);
        return res;
    }

    public static IScalar[] VectorSub(IScalar[] a, IScalar[] b, IGroup group)
    {
        a = PadVector(a, b.Length, group);
        b = PadVector(b, a.Length, group);
        var res = new IScalar[a.Length];
        for (int i = 0; i < res.Length; i++)
            res[i] = a[i].Sub(b[i]);
        return res;
    }

    public static IScalar[] VectorMulOnScalar(IScalar[] a, IScalar c)
    {
        var res = new IScalar[a.Length];
        for (int i = 0; i < res.Length; i++)
            res[i] = a[i].Mul(c);
        return res;
    }

    /// <summary>Inner (dot) product of two scalar vectors.</summary>
    public static IScalar VectorMul(IScalar[] a, IScalar[] b, IGroup group)
    {
        a = PadVector(a, b.Length, group);
        b = PadVector(b, a.Length, group);
        var res = group.ScalarFromInt(0);
        for (int i = 0; i < a.Length; i++)
            res = res.Add(a[i].Mul(b[i]));
        return res;
    }

    /// <summary>Weighted inner product: sum(a[i] * b[i] * mu^(i+1)).</summary>
    public static IScalar WeightVectorMul(IScalar[] a, IScalar[] b, IScalar mu, IGroup group)
    {
        a = PadVector(a, b.Length, group);
        b = PadVector(b, a.Length, group);
        var res = group.ScalarFromInt(0);
        var exp = mu;
        for (int i = 0; i < a.Length; i++)
        {
            res = res.Add(a[i].Mul(b[i]).Mul(exp));
            exp = exp.Mul(mu);
        }
        return res;
    }

    /// <summary>Hadamard (element-wise) product.</summary>
    public static IScalar[] HadamardMul(IScalar[] a, IScalar[] b)
    {
        var res = new IScalar[a.Length];
        for (int i = 0; i < res.Length; i++)
            res[i] = a[i].Mul(b[i]);
        return res;
    }

    /// <summary>Tensor product: for each element in b, multiply entire vector a by it.</summary>
    public static IScalar[] VectorTensorMul(IScalar[] a, IScalar[] b)
    {
        var res = new IScalar[a.Length * b.Length];
        for (int i = 0; i < b.Length; i++)
        {
            var scaled = VectorMulOnScalar(a, b[i]);
            Array.Copy(scaled, 0, res, i * a.Length, a.Length);
        }
        return res;
    }

    /// <summary>Power vector: [1, v, v^2, v^3, ..., v^(a-1)].</summary>
    public static IScalar[] E(IScalar v, int a, IGroup group)
    {
        var val = group.ScalarFromInt(1);
        var res = new IScalar[a];
        for (int i = 0; i < a; i++)
        {
            res[i] = val;
            val = val.Mul(v);
        }
        return res;
    }

    // ─── Point vector operations ───

    /// <summary>Linear combination: sum(g[i] * a[i]).</summary>
    public static IPoint VectorPointScalarMul(IPoint[] g, IScalar[] a, IGroup group)
    {
        if (g.Length == 0)
            return group.Infinity;

        a = PadVector(a, g.Length, group);

        var res = g[0].ScalarMul(a[0]);
        for (int i = 1; i < g.Length; i++)
            res = res.Add(g[i].ScalarMul(a[i]));
        return res;
    }

    /// <summary>Element-wise point addition.</summary>
    public static IPoint[] VectorPointsAdd(IPoint[] a, IPoint[] b, IGroup group)
    {
        a = PadPoints(a, b.Length, group);
        b = PadPoints(b, a.Length, group);
        var res = new IPoint[a.Length];
        for (int i = 0; i < res.Length; i++)
            res[i] = a[i].Add(b[i]);
        return res;
    }

    /// <summary>Scalar multiplication of each point in vector by same scalar.</summary>
    public static IPoint[] VectorPointMulOnScalar(IPoint[] g, IScalar a)
    {
        var res = new IPoint[g.Length];
        for (int i = 0; i < res.Length; i++)
            res[i] = g[i].ScalarMul(a);
        return res;
    }

    // ─── Matrix operations ───

    public static IScalar[][] ZeroMatrix(IGroup group, int n, int m)
    {
        var res = new IScalar[n][];
        for (int i = 0; i < n; i++)
        {
            res[i] = new IScalar[m];
            for (int j = 0; j < m; j++)
                res[i][j] = group.ScalarFromInt(0);
        }
        return res;
    }

    /// <summary>Diagonal inverse matrix: diag(x^-1, x^-2, ..., x^-n).</summary>
    public static IScalar[][] DiagInv(IScalar x, int n, IGroup group)
    {
        var res = new IScalar[n][];
        var xinv = x.Inv();
        var val = xinv;

        for (int i = 0; i < n; i++)
        {
            res[i] = new IScalar[n];
            for (int j = 0; j < n; j++)
                res[i][j] = i == j ? val : group.ScalarFromInt(0);
            if (i < n - 1)
                val = val.Mul(xinv);
        }
        return res;
    }

    /// <summary>Row vector * matrix: result[j] = dot(a, column_j(m)).</summary>
    public static IScalar[] VectorMulOnMatrix(IScalar[] a, IScalar[][] m, IGroup group)
    {
        var cols = m[0].Length;
        var res = new IScalar[cols];
        for (int j = 0; j < cols; j++)
        {
            var column = new IScalar[m.Length];
            for (int i = 0; i < m.Length; i++)
                column[i] = m[i][j];
            res[j] = VectorMul(a, column, group);
        }
        return res;
    }

    /// <summary>Matrix * column vector: result[i] = dot(row_i(m), a).</summary>
    public static IScalar[] MatrixMulOnVector(IScalar[] a, IScalar[][] m, IGroup group)
    {
        var res = new IScalar[m.Length];
        for (int i = 0; i < m.Length; i++)
            res[i] = VectorMul(a, m[i], group);
        return res;
    }

    // ─── Helpers ───

    /// <summary>Split vector into even/odd indexed elements.</summary>
    public static (IScalar[] even, IScalar[] odd) ReduceVector(IScalar[] v)
    {
        var even = new List<IScalar>();
        var odd = new List<IScalar>();
        for (int i = 0; i < v.Length; i++)
        {
            if (i % 2 == 0) even.Add(v[i]);
            else odd.Add(v[i]);
        }
        return (even.ToArray(), odd.ToArray());
    }

    /// <summary>Split point vector into even/odd indexed elements.</summary>
    public static (IPoint[] even, IPoint[] odd) ReducePoints(IPoint[] v)
    {
        var even = new List<IPoint>();
        var odd = new List<IPoint>();
        for (int i = 0; i < v.Length; i++)
        {
            if (i % 2 == 0) even.Add(v[i]);
            else odd.Add(v[i]);
        }
        return (even.ToArray(), odd.ToArray());
    }

    public static int PowerOfTwo(int x)
    {
        int p2 = 1;
        while (p2 < x) p2 *= 2;
        return p2;
    }

    private static IScalar[] PadVector(IScalar[] v, int minLen, IGroup group)
    {
        if (v.Length >= minLen) return v;
        var padded = new IScalar[minLen];
        Array.Copy(v, padded, v.Length);
        for (int i = v.Length; i < minLen; i++)
            padded[i] = group.ScalarFromInt(0);
        return padded;
    }

    private static IPoint[] PadPoints(IPoint[] v, int minLen, IGroup group)
    {
        if (v.Length >= minLen) return v;
        var padded = new IPoint[minLen];
        Array.Copy(v, padded, v.Length);
        for (int i = v.Length; i < minLen; i++)
            padded[i] = group.Infinity;
        return padded;
    }
}
