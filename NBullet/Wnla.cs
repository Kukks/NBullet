using static NBullet.VectorMath;

namespace NBullet;

/// <summary>
/// Weight Norm Linear Argument (WNLA) protocol.
/// Proves knowledge of vectors l, n satisfying commitment C = v*G + &lt;l,H&gt; + &lt;n,G&gt;
/// where v = &lt;c,l&gt; + |n^2|_mu.
/// </summary>
public static class Wnla
{
    /// <summary>
    /// Creates a commitment for vectors n, l based on public parameters.
    /// Commit(l, n) = v*G + &lt;l, H&gt; + &lt;n, GVec&gt;
    /// where v = &lt;c, l&gt; + |n^2|_mu
    /// </summary>
    public static IPoint CommitWnla(WeightNormLinearPublic pub, IScalar[] l, IScalar[] n, IGroup group)
    {
        var v = VectorMul(pub.C, l, group).Add(WeightVectorMul(n, n, pub.Mu, group));
        var c = pub.G.ScalarMul(v);
        c = c.Add(VectorPointScalarMul(pub.HVec, l, group));
        c = c.Add(VectorPointScalarMul(pub.GVec, n, group));
        return c;
    }

    /// <summary>
    /// Verifies the weight norm linear argument proof. Returns null if valid, error message otherwise.
    /// </summary>
    public static string? VerifyWnla(WeightNormLinearPublic pub, WeightNormLinearArgumentProof proof,
        IPoint com, IFiatShamirEngine fs, IGroup group)
    {
        if (proof.X.Length != proof.R.Length)
            return "invalid length for R and X vectors: should be equal";

        if (proof.X.Length == 0)
        {
            var expected = CommitWnla(pub, proof.L, proof.N, group);
            if (!expected.Eq(com))
                return "failed to verify proof";
            return null;
        }

        fs.AddPoint(com);
        fs.AddPoint(proof.X[0]);
        fs.AddPoint(proof.R[0]);
        fs.AddScalar(group.ScalarFromInt(pub.HVec.Length));
        fs.AddScalar(group.ScalarFromInt(pub.GVec.Length));

        var y = fs.GetChallenge(group);

        var (c0, c1) = ReduceVector(pub.C);
        var (g0, g1) = ReducePoints(pub.GVec);
        var (h0, h1) = ReducePoints(pub.HVec);

        var h_ = VectorPointsAdd(h0, VectorPointMulOnScalar(h1, y), group);
        var g_ = VectorPointsAdd(VectorPointMulOnScalar(g0, pub.Ro), VectorPointMulOnScalar(g1, y), group);
        var c_ = VectorAdd(c0, VectorMulOnScalar(c1, y), group);

        var com_ = com.Add(proof.X[0].ScalarMul(y));
        var yy_minus_1 = y.Mul(y).Sub(group.ScalarFromInt(1));
        com_ = com_.Add(proof.R[0].ScalarMul(yy_minus_1));

        return VerifyWnla(
            new WeightNormLinearPublic
            {
                G = pub.G,
                GVec = g_,
                HVec = h_,
                C = c_,
                Ro = pub.Mu,
                Mu = pub.Mu.Mul(pub.Mu)
            },
            new WeightNormLinearArgumentProof
            {
                R = proof.R[1..],
                X = proof.X[1..],
                L = proof.L,
                N = proof.N
            },
            com_,
            fs,
            group
        );
    }

    /// <summary>
    /// Generates zero knowledge proof of knowledge of two vectors l and n.
    /// </summary>
    public static WeightNormLinearArgumentProof ProveWnla(WeightNormLinearPublic pub, IPoint com,
        IFiatShamirEngine fs, IScalar[] l, IScalar[] n, IGroup group)
    {
        if (l.Length + n.Length < 6)
        {
            return new WeightNormLinearArgumentProof
            {
                R = Array.Empty<IPoint>(),
                X = Array.Empty<IPoint>(),
                L = l,
                N = n
            };
        }

        var roinv = pub.Ro.Inv();

        var (c0, c1) = ReduceVector(pub.C);
        var (l0, l1) = ReduceVector(l);
        var (n0, n1) = ReduceVector(n);
        var (g0, g1) = ReducePoints(pub.GVec);
        var (h0, h1) = ReducePoints(pub.HVec);

        var mu2 = pub.Mu.Mul(pub.Mu);

        var vx = WeightVectorMul(n0, n1, mu2, group)
            .Mul(group.ScalarFromInt(2)).Mul(roinv)
            .Add(VectorMul(c0, l1, group))
            .Add(VectorMul(c1, l0, group));

        var vr = WeightVectorMul(n1, n1, mu2, group)
            .Add(VectorMul(c1, l1, group));

        var xPoint = pub.G.ScalarMul(vx);
        xPoint = xPoint.Add(VectorPointScalarMul(h0, l1, group));
        xPoint = xPoint.Add(VectorPointScalarMul(h1, l0, group));
        xPoint = xPoint.Add(VectorPointScalarMul(g0, VectorMulOnScalar(n1, pub.Ro), group));
        xPoint = xPoint.Add(VectorPointScalarMul(g1, VectorMulOnScalar(n0, roinv), group));

        var rPoint = pub.G.ScalarMul(vr);
        rPoint = rPoint.Add(VectorPointScalarMul(h1, l1, group));
        rPoint = rPoint.Add(VectorPointScalarMul(g1, n1, group));

        fs.AddPoint(com);
        fs.AddPoint(xPoint);
        fs.AddPoint(rPoint);
        fs.AddScalar(group.ScalarFromInt(pub.HVec.Length));
        fs.AddScalar(group.ScalarFromInt(pub.GVec.Length));

        var y = fs.GetChallenge(group);

        var h_ = VectorPointsAdd(h0, VectorPointMulOnScalar(h1, y), group);
        var g_ = VectorPointsAdd(VectorPointMulOnScalar(g0, pub.Ro), VectorPointMulOnScalar(g1, y), group);
        var c_ = VectorAdd(c0, VectorMulOnScalar(c1, y), group);

        var l_ = VectorAdd(l0, VectorMulOnScalar(l1, y), group);
        var n_ = VectorAdd(VectorMulOnScalar(n0, roinv), VectorMulOnScalar(n1, y), group);

        var pub_ = new WeightNormLinearPublic
        {
            G = pub.G,
            GVec = g_,
            HVec = h_,
            C = c_,
            Ro = pub.Mu,
            Mu = mu2
        };

        var res = ProveWnla(pub_, CommitWnla(pub_, l_, n_, group), fs, l_, n_, group);

        return new WeightNormLinearArgumentProof
        {
            R = new[] { rPoint }.Concat(res.R).ToArray(),
            X = new[] { xPoint }.Concat(res.X).ToArray(),
            L = res.L,
            N = res.N
        };
    }

    /// <summary>
    /// Creates a new WeightNormLinearPublic with random parameters for testing.
    /// </summary>
    public static WeightNormLinearPublic NewWeightNormLinearPublic(int lLen, int nLen, IGroup group)
    {
        var gvec = new IPoint[nLen];
        for (int i = 0; i < nLen; i++)
            gvec[i] = group.RandomPoint();

        var hvec = new IPoint[lLen];
        for (int i = 0; i < lLen; i++)
            hvec[i] = group.RandomPoint();

        var c = new IScalar[lLen];
        for (int i = 0; i < lLen; i++)
            c[i] = group.RandomScalar();

        var ro = group.RandomScalar();

        return new WeightNormLinearPublic
        {
            G = group.RandomPoint(),
            GVec = gvec,
            HVec = hvec,
            C = c,
            Ro = ro,
            Mu = ro.Mul(ro)
        };
    }
}
