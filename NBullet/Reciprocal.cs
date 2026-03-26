using static NBullet.VectorMath;

namespace NBullet;

/// <summary>
/// Reciprocal range proofs: proves a committed value lies in [0, 2^n) using hex decomposition
/// and arithmetic circuit proofs.
/// </summary>
public static class Reciprocal
{
    public static IPoint CommitValue(ReciprocalPublic pub, IScalar v, IScalar s)
    {
        var res = pub.G.ScalarMul(v);
        res = res.Add(pub.HVec[0].ScalarMul(s));
        return res;
    }

    public static IPoint CommitPoles(ReciprocalPublic pub, IScalar[] r, IScalar s, IGroup group)
    {
        var res = pub.HVec[0].ScalarMul(s);
        res = res.Add(VectorPointScalarMul(pub.HVec[9..], r, group));
        return res;
    }

    /// <summary>
    /// Generates zero knowledge proof that the committed value lies in [0, 2^n) range.
    /// </summary>
    public static ReciprocalProof ProveRange(ReciprocalPublic pub, IFiatShamirEngine fs,
        ReciprocalPrivate priv, IGroup group)
    {
        var vCom = CommitValue(pub, priv.X, priv.S);
        fs.AddPoint(vCom);

        var e = fs.GetChallenge(group);

        int Nm = pub.Nd;
        int No = pub.Np;
        int Nv = pub.Nd + 1;
        int Nl = Nv;
        int Nw = pub.Nd + pub.Nd + pub.Np;

        var r = new IScalar[pub.Nd];
        for (int j = 0; j < r.Length; j++)
            r[j] = priv.Digits[j].Add(e).Inv();

        var rBlind = group.RandomScalar();
        var rCom = CommitPoles(pub, r, rBlind, group);

        var v = new IScalar[] { priv.X }.Concat(r).ToArray();
        var wL = priv.Digits;
        var wR = r;
        var wO = priv.M;

        var am = OneVector(group, Nm);
        var Wm = ZeroMatrix(group, Nm, Nw);
        for (int i = 0; i < Nm; i++)
            Wm[i][i + Nm] = e.Negate();

        var al = ZeroVector(group, Nl);
        var Wl = ZeroMatrix(group, Nl, Nw);

        var baseVal = group.ScalarFromInt(pub.Np);
        for (int i = 0; i < Nm; i++)
            Wl[0][i] = group.Pow(baseVal, i).Negate();

        for (int i = 0; i < Nm; i++)
            for (int j = 0; j < Nm; j++)
                Wl[i + 1][j + Nm] = group.ScalarFromInt(1);

        for (int i = 0; i < Nm; i++)
            Wl[i + 1][i + Nm] = group.ScalarFromInt(0);

        for (int i = 0; i < Nm; i++)
            for (int j = 0; j < No; j++)
                Wl[i + 1][j + 2 * Nm] = e.Add(group.ScalarFromInt(j)).Inv().Negate();

        var circuit = new ArithmeticCircuitPublic
        {
            Nm = Nm, Nl = Nl, Nv = Nv, Nw = Nw, No = No, K = 1,
            G = pub.G, GVec = pub.GVec, HVec = pub.HVec,
            Wm = Wm, Wl = Wl, Am = am, Al = al,
            Fl = true, Fm = false,
            F = (typ, index) => typ == PartitionType.LL && index < No ? index : (int?)null,
            GVec_ = pub.GVec_, HVec_ = pub.HVec_
        };

        var circuitPriv = new ArithmeticCircuitPrivate
        {
            V = new[] { v },
            Sv = new[] { priv.S.Add(rBlind) },
            Wl = wL, Wr = wR, Wo = wO
        };

        var vCommit = ArithmeticCircuit.CommitCircuit(circuit, circuitPriv.V[0], circuitPriv.Sv[0], group);

        return new ReciprocalProof
        {
            CircuitProof = ArithmeticCircuit.ProveCircuit(circuit, new[] { vCommit }, fs, circuitPriv, group),
            V = rCom
        };
    }

    /// <summary>
    /// Verifies BP++ reciprocal argument range proof. Returns null if valid, error message otherwise.
    /// </summary>
    public static string? VerifyRange(ReciprocalPublic pub, IPoint vCom, IFiatShamirEngine fs,
        ReciprocalProof proof, IGroup group)
    {
        fs.AddPoint(vCom);

        var e = fs.GetChallenge(group);

        int Nm = pub.Nd;
        int No = pub.Np;
        int Nv = pub.Nd + 1;
        int Nl = Nv;
        int Nw = pub.Nd + pub.Nd + pub.Np;

        var am = OneVector(group, Nm);
        var Wm = ZeroMatrix(group, Nm, Nw);
        for (int i = 0; i < Nm; i++)
            Wm[i][i + Nm] = e.Negate();

        var al = ZeroVector(group, Nl);
        var Wl = ZeroMatrix(group, Nl, Nw);

        var baseVal = group.ScalarFromInt(pub.Np);
        for (int i = 0; i < Nm; i++)
            Wl[0][i] = group.Pow(baseVal, i).Negate();

        for (int i = 0; i < Nm; i++)
            for (int j = 0; j < Nm; j++)
                Wl[i + 1][j + Nm] = group.ScalarFromInt(1);

        for (int i = 0; i < Nm; i++)
            Wl[i + 1][i + Nm] = group.ScalarFromInt(0);

        for (int i = 0; i < Nm; i++)
            for (int j = 0; j < No; j++)
                Wl[i + 1][j + 2 * Nm] = e.Add(group.ScalarFromInt(j)).Inv().Negate();

        var circuit = new ArithmeticCircuitPublic
        {
            Nm = Nm, Nl = Nl, Nv = Nv, Nw = Nw, No = No, K = 1,
            G = pub.G, GVec = pub.GVec, HVec = pub.HVec,
            Wm = Wm, Wl = Wl, Am = am, Al = al,
            Fl = true, Fm = false,
            F = (typ, index) => typ == PartitionType.LL && index < No ? index : (int?)null,
            GVec_ = pub.GVec_, HVec_ = pub.HVec_
        };

        var combined = vCom.Add(proof.V);

        return ArithmeticCircuit.VerifyCircuit(circuit, new[] { combined }, fs, proof.CircuitProof, group);
    }
}
