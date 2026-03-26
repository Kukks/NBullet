using static NBullet.VectorMath;

namespace NBullet;

/// <summary>
/// BP++ arithmetic circuit zero-knowledge proof using WNLA protocol.
/// </summary>
public static class ArithmeticCircuit
{
    public static IPoint CommitCircuit(ArithmeticCircuitPublic pub, IScalar[] v, IScalar s, IGroup group)
    {
        var res = pub.G.ScalarMul(v[0]);
        res = res.Add(pub.HVec[0].ScalarMul(s));
        res = res.Add(VectorPointScalarMul(pub.HVec[9..], v[1..], group));
        return res;
    }

    public static string? VerifyCircuit(ArithmeticCircuitPublic pub, IPoint[] V,
        IFiatShamirEngine fs, ArithmeticCircuitProof proof, IGroup group)
    {
        fs.AddPoint(proof.CL);
        fs.AddPoint(proof.CR);
        fs.AddPoint(proof.CO);

        foreach (var vi in V)
            fs.AddPoint(vi);

        var ro = fs.GetChallenge(group);
        var lambda = fs.GetChallenge(group);
        var beta = fs.GetChallenge(group);
        var delta = fs.GetChallenge(group);

        var (MlnL, MmnL, MlnR, MmnR) = CalculateMRL(pub);
        var (MlnO, MmnO, MllL, MmlL, MllR, MmlR, MllO, MmlO) = CalculateMO(pub, group);

        var mu = ro.Mul(ro);
        var one = group.ScalarFromInt(1);
        var two = group.ScalarFromInt(2);

        IScalar Lcomb(int i) => (pub.Fl ? group.Pow(lambda, pub.Nv * i) : group.ScalarFromInt(0))
            .Add(pub.Fm ? group.Pow(mu, pub.Nv * i + 1) : group.ScalarFromInt(0));

        // Calculate linear combination of V
        var vSum = group.Infinity;
        for (int i = 0; i < pub.K; i++)
            vSum = vSum.Add(V[i].ScalarMul(Lcomb(i)));
        vSum = vSum.ScalarMul(two);

        // Calculate lambda vector
        var lambdaVec = CalculateLambdaVec(pub, lambda, mu, group);
        var muVec = VectorMulOnScalar(E(mu, pub.Nm, group), mu);
        var muDiagInv = DiagInv(mu, pub.Nm, group);

        var cnL = VectorMulOnMatrix(VectorSub(VectorMulOnMatrix(lambdaVec, MlnL, group), VectorMulOnMatrix(muVec, MmnL, group), group), muDiagInv, group);
        var cnR = VectorMulOnMatrix(VectorSub(VectorMulOnMatrix(lambdaVec, MlnR, group), VectorMulOnMatrix(muVec, MmnR, group), group), muDiagInv, group);
        var cnO = VectorMulOnMatrix(VectorSub(VectorMulOnMatrix(lambdaVec, MlnO, group), VectorMulOnMatrix(muVec, MmnO, group), group), muDiagInv, group);

        var clL = VectorSub(VectorMulOnMatrix(lambdaVec, MllL, group), VectorMulOnMatrix(muVec, MmlL, group), group);
        var clR = VectorSub(VectorMulOnMatrix(lambdaVec, MllR, group), VectorMulOnMatrix(muVec, MmlR, group), group);
        var clO = VectorSub(VectorMulOnMatrix(lambdaVec, MllO, group), VectorMulOnMatrix(muVec, MmlO, group), group);

        fs.AddPoint(proof.CS!);

        var t = fs.GetChallenge(group);
        var tinv = t.Inv();
        var t2 = t.Mul(t);
        var t3 = t2.Mul(t);

        var pnT = VectorMulOnScalar(cnO, delta.Inv().Mul(t3));
        pnT = VectorSub(pnT, VectorMulOnScalar(cnL, t2), group);
        pnT = VectorAdd(pnT, VectorMulOnScalar(cnR, t), group);

        var psT = WeightVectorMul(pnT, pnT, mu, group);
        psT = psT.Add(two.Mul(VectorMul(lambdaVec, pub.Al, group)).Mul(t3));
        psT = psT.Sub(two.Mul(VectorMul(muVec, pub.Am, group)).Mul(t3));

        var PT = pub.G.ScalarMul(psT);
        PT = PT.Add(VectorPointScalarMul(pub.GVec, pnT, group));

        var cr_T = BuildCrT(beta, tinv, t, t2, t3, group);

        var cl0 = CalculateCl0(pub, lambda, mu, group);

        var cl_T = VectorMulOnScalar(clO, t3.Mul(delta.Inv()));
        cl_T = VectorSub(cl_T, VectorMulOnScalar(clL, t2), group);
        cl_T = VectorAdd(cl_T, VectorMulOnScalar(clR, t), group);
        cl_T = VectorMulOnScalar(cl_T, two);
        cl_T = VectorSub(cl_T, cl0, group);

        var cT = cr_T.Concat(cl_T).ToArray();

        var CT = PT.Add(proof.CS!.ScalarMul(tinv));
        CT = CT.Add(proof.CO.ScalarMul(delta.Negate()));
        CT = CT.Add(proof.CL.ScalarMul(t));
        CT = CT.Add(proof.CR.ScalarMul(t2.Negate()));
        CT = CT.Add(vSum.ScalarMul(t3));

        return Wnla.VerifyWnla(
            new WeightNormLinearPublic
            {
                G = pub.G,
                GVec = pub.GVec.Concat(pub.GVec_).ToArray(),
                HVec = pub.HVec.Concat(pub.HVec_).ToArray(),
                C = cT,
                Ro = ro,
                Mu = mu
            },
            proof.WNLA!,
            CT,
            fs,
            group
        );
    }

    public static ArithmeticCircuitProof ProveCircuit(ArithmeticCircuitPublic pub, IPoint[] V,
        IFiatShamirEngine fs, ArithmeticCircuitPrivate priv, IGroup group)
    {
        var (ro_vals, rl, no, nl, lo, ll, Co, Cl) = CommitOL(pub, priv.Wo, priv.Wl, group);
        var (rr, nr, lr, Cr) = CommitR(pub, priv.Wo, priv.Wr, group);

        fs.AddPoint(Cl);
        fs.AddPoint(Cr);
        fs.AddPoint(Co);

        foreach (var vi in V)
            fs.AddPoint(vi);

        return InnerProve(pub, fs, priv,
            new[] { rl, rr, ro_vals },
            new[] { nl, nr, no },
            new[] { ll, lr, lo },
            new[] { Cl, Cr, Co },
            V, group);
    }

    private static (IScalar[] ro, IScalar[] rl, IScalar[] no, IScalar[] nl,
        IScalar[] lo, IScalar[] ll, IPoint Co, IPoint Cl)
        CommitOL(ArithmeticCircuitPublic pub, IScalar[] wo, IScalar[] wl, IGroup group)
    {
        var zero = group.ScalarFromInt(0);

        var ro = new IScalar[]
        {
            group.RandomScalar(), group.RandomScalar(), group.RandomScalar(), group.RandomScalar(),
            zero, group.RandomScalar(), group.RandomScalar(), group.RandomScalar(), zero
        };

        var rl = new IScalar[]
        {
            group.RandomScalar(), group.RandomScalar(), group.RandomScalar(), zero,
            group.RandomScalar(), group.RandomScalar(), group.RandomScalar(), zero, zero
        };

        var nl = wl;

        var no = new IScalar[pub.Nm];
        for (int j = 0; j < pub.Nm; j++)
        {
            no[j] = zero;
            var idx = pub.F(PartitionType.NO, j);
            if (idx.HasValue) no[j] = wo[idx.Value];
        }

        var lo = new IScalar[pub.Nv];
        for (int j = 0; j < pub.Nv; j++)
        {
            lo[j] = zero;
            var idx = pub.F(PartitionType.LO, j);
            if (idx.HasValue) lo[j] = wo[idx.Value];
        }

        var ll = new IScalar[pub.Nv];
        for (int j = 0; j < pub.Nv; j++)
        {
            ll[j] = zero;
            var idx = pub.F(PartitionType.LL, j);
            if (idx.HasValue) ll[j] = wo[idx.Value];
        }

        var Co = VectorPointScalarMul(pub.HVec, ro.Concat(lo).ToArray(), group);
        Co = Co.Add(VectorPointScalarMul(pub.GVec, no, group));

        var Cl = VectorPointScalarMul(pub.HVec, rl.Concat(ll).ToArray(), group);
        Cl = Cl.Add(VectorPointScalarMul(pub.GVec, nl, group));

        return (ro, rl, no, nl, lo, ll, Co, Cl);
    }

    private static (IScalar[] rr, IScalar[] nr, IScalar[] lr, IPoint Cr)
        CommitR(ArithmeticCircuitPublic pub, IScalar[] wo, IScalar[] wr, IGroup group)
    {
        var zero = group.ScalarFromInt(0);

        var rr = new IScalar[]
        {
            group.RandomScalar(), group.RandomScalar(), zero, group.RandomScalar(),
            group.RandomScalar(), group.RandomScalar(), zero, zero, zero
        };

        var nr = wr;

        var lr = new IScalar[pub.Nv];
        for (int j = 0; j < pub.Nv; j++)
        {
            lr[j] = zero;
            var idx = pub.F(PartitionType.LR, j);
            if (idx.HasValue) lr[j] = wo[idx.Value];
        }

        var Cr = VectorPointScalarMul(pub.HVec, rr.Concat(lr).ToArray(), group);
        Cr = Cr.Add(VectorPointScalarMul(pub.GVec, nr, group));

        return (rr, nr, lr, Cr);
    }

    private static ArithmeticCircuitProof InnerProve(ArithmeticCircuitPublic pub,
        IFiatShamirEngine fs, ArithmeticCircuitPrivate priv,
        IScalar[][] r, IScalar[][] n, IScalar[][] l, IPoint[] C, IPoint[] V, IGroup group)
    {
        var rl = r[0]; var rr = r[1]; var ro = r[2];
        var ll = l[0]; var lr = l[1]; var lo = l[2];
        var nl = n[0]; var nr = n[1]; var no = n[2];
        var Cl = C[0]; var Cr = C[1]; var Co = C[2];

        var proof = new ArithmeticCircuitProof { CL = Cl, CR = Cr, CO = Co };

        var zero = group.ScalarFromInt(0);
        var one = group.ScalarFromInt(1);
        var two = group.ScalarFromInt(2);

        var rho = fs.GetChallenge(group);
        var lambda = fs.GetChallenge(group);
        var beta = fs.GetChallenge(group);
        var delta = fs.GetChallenge(group);

        var (MlnL, MmnL, MlnR, MmnR) = CalculateMRL(pub);
        var (MlnO, MmnO, MllL, MmlL, MllR, MmlR, MllO, MmlO) = CalculateMO(pub, group);

        var mu = rho.Mul(rho);

        var lambdaVec = CalculateLambdaVec(pub, lambda, mu, group);
        var muVec = VectorMulOnScalar(E(mu, pub.Nm, group), mu);
        var muDiagInv = DiagInv(mu, pub.Nm, group);

        var cnL = VectorMulOnMatrix(VectorSub(VectorMulOnMatrix(lambdaVec, MlnL, group), VectorMulOnMatrix(muVec, MmnL, group), group), muDiagInv, group);
        var cnR = VectorMulOnMatrix(VectorSub(VectorMulOnMatrix(lambdaVec, MlnR, group), VectorMulOnMatrix(muVec, MmnR, group), group), muDiagInv, group);
        var cnO = VectorMulOnMatrix(VectorSub(VectorMulOnMatrix(lambdaVec, MlnO, group), VectorMulOnMatrix(muVec, MmnO, group), group), muDiagInv, group);

        var clL = VectorSub(VectorMulOnMatrix(lambdaVec, MllL, group), VectorMulOnMatrix(muVec, MmlL, group), group);
        var clR = VectorSub(VectorMulOnMatrix(lambdaVec, MllR, group), VectorMulOnMatrix(muVec, MmlR, group), group);
        var clO = VectorSub(VectorMulOnMatrix(lambdaVec, MllO, group), VectorMulOnMatrix(muVec, MmlO, group), group);

        // Prover computes random ls, ns
        var ls = new IScalar[pub.Nv];
        for (int i = 0; i < pub.Nv; i++) ls[i] = group.RandomScalar();

        var ns = new IScalar[pub.Nm];
        for (int i = 0; i < pub.Nm; i++) ns[i] = group.RandomScalar();

        IScalar Lcomb(int i) => (pub.Fl ? group.Pow(lambda, pub.Nv * i) : zero)
            .Add(pub.Fm ? group.Pow(mu, pub.Nv * i + 1) : zero);

        // Calc linear combination of v[][0]
        var v_ = zero;
        for (int i = 0; i < pub.K; i++)
            v_ = v_.Add(priv.V[i][0].Mul(Lcomb(i)));
        v_ = v_.Mul(two);

        var rv = ZeroVector(group, 9);
        var rv0 = zero;
        for (int i = 0; i < pub.K; i++)
            rv0 = rv0.Add(priv.Sv[i].Mul(Lcomb(i)));
        rv[0] = rv0.Mul(two);

        // Calc linear combination of v[][1:]
        var v_1 = ZeroVector(group, 1);
        for (int i = 0; i < pub.K; i++)
            v_1 = VectorAdd(v_1, VectorMulOnScalar(priv.V[i][1..], Lcomb(i)), group);
        v_1 = VectorMulOnScalar(v_1, two);

        var cl0 = CalculateCl0(pub, lambda, mu, group);

        // Define f'(t) polynomial coefficients
        var f_ = new Dictionary<int, IScalar>();
        for (int k = -2; k <= 6; k++) f_[k] = zero;

        f_[-2] = f_[-2].Sub(WeightVectorMul(ns, ns, mu, group));

        f_[-1] = f_[-1].Add(VectorMul(cl0, ls, group));
        f_[-1] = f_[-1].Add(two.Mul(delta).Mul(WeightVectorMul(ns, no, mu, group)));

        f_[0] = f_[0].Sub(two.Mul(VectorMul(clR, ls, group)));
        f_[0] = f_[0].Sub(delta.Mul(VectorMul(cl0, lo, group)));
        f_[0] = f_[0].Sub(WeightVectorMul(ns, VectorAdd(nl, cnR, group), mu, group).Mul(two));
        f_[0] = f_[0].Sub(delta.Mul(delta).Mul(WeightVectorMul(no, no, mu, group)));

        f_[1] = f_[1].Add(two.Mul(VectorMul(clL, ls, group)));
        f_[1] = f_[1].Add(two.Mul(delta).Mul(VectorMul(clR, lo, group)));
        f_[1] = f_[1].Add(VectorMul(cl0, ll, group));
        f_[1] = f_[1].Add(WeightVectorMul(ns, VectorAdd(nr, cnL, group), mu, group).Mul(two));
        f_[1] = f_[1].Add(WeightVectorMul(no, VectorAdd(nl, cnR, group), mu, group).Mul(two).Mul(delta));

        var dinv = delta.Inv();
        f_[2] = f_[2].Add(WeightVectorMul(cnR, cnR, mu, group));
        f_[2] = f_[2].Sub(two.Mul(dinv).Mul(VectorMul(clO, ls, group)));
        f_[2] = f_[2].Sub(two.Mul(delta).Mul(VectorMul(clL, lo, group)));
        f_[2] = f_[2].Sub(two.Mul(VectorMul(clR, ll, group)));
        f_[2] = f_[2].Sub(VectorMul(cl0, lr, group));
        f_[2] = f_[2].Sub(two.Mul(dinv).Mul(WeightVectorMul(ns, cnO, mu, group)));
        f_[2] = f_[2].Sub(two.Mul(delta).Mul(WeightVectorMul(no, VectorAdd(nr, cnL, group), mu, group)));
        f_[2] = f_[2].Sub(WeightVectorMul(VectorAdd(nl, cnR, group), VectorAdd(nl, cnR, group), mu, group));

        // f_[3] should be zero (by construction), but we compute it
        f_[3] = f_[3].Add(two.Mul(VectorMul(lambdaVec, pub.Al, group).Sub(VectorMul(muVec, pub.Am, group))));
        f_[3] = f_[3].Sub(two.Mul(WeightVectorMul(cnL, cnR, mu, group)));
        f_[3] = f_[3].Add(v_);
        f_[3] = f_[3].Add(two.Mul(VectorMul(clO, lo, group)));
        f_[3] = f_[3].Add(two.Mul(VectorMul(clL, ll, group)));
        f_[3] = f_[3].Add(two.Mul(VectorMul(clR, lr, group)));
        f_[3] = f_[3].Add(VectorMul(cl0, v_1, group));
        f_[3] = f_[3].Add(WeightVectorMul(no, cnO, mu, group).Mul(two));
        f_[3] = f_[3].Add(WeightVectorMul(VectorAdd(nl, cnR, group), VectorAdd(nr, cnL, group), mu, group).Mul(two));

        f_[4] = f_[4].Add(two.Mul(dinv).Mul(WeightVectorMul(cnO, cnR, mu, group)));
        f_[4] = f_[4].Add(WeightVectorMul(cnL, cnL, mu, group));
        f_[4] = f_[4].Sub(two.Mul(dinv).Mul(VectorMul(clO, ll, group)));
        f_[4] = f_[4].Sub(two.Mul(VectorMul(clL, lr, group)));
        f_[4] = f_[4].Sub(two.Mul(VectorMul(clR, v_1, group)));
        f_[4] = f_[4].Sub(two.Mul(dinv).Mul(WeightVectorMul(VectorAdd(nl, cnR, group), cnO, mu, group)));
        f_[4] = f_[4].Sub(WeightVectorMul(VectorAdd(nr, cnL, group), VectorAdd(nr, cnL, group), mu, group));

        f_[5] = f_[5].Sub(two.Mul(dinv).Mul(WeightVectorMul(cnO, cnL, mu, group)));
        f_[5] = f_[5].Add(two.Mul(dinv).Mul(VectorMul(clO, lr, group)));
        f_[5] = f_[5].Add(two.Mul(VectorMul(clL, v_1, group)));
        f_[5] = f_[5].Add(two.Mul(dinv).Mul(WeightVectorMul(VectorAdd(nr, cnL, group), cnO, mu, group)));

        f_[6] = f_[6].Sub(two.Mul(dinv).Mul(VectorMul(clO, v_1, group)));

        var ch_beta_inv = beta.Inv();

        var rs = new IScalar[]
        {
            f_[-1].Add(beta.Mul(delta).Mul(ro[1])),
            f_[-2].Mul(ch_beta_inv),
            f_[0].Add(delta.Mul(ro[0])).Mul(ch_beta_inv).Sub(rl[1]),
            f_[1].Sub(rl[0]).Mul(ch_beta_inv).Add(rr[1]).Add(delta.Mul(ro[2])),
            f_[2].Add(rr[0]).Mul(ch_beta_inv).Add(delta.Mul(ro[3]).Sub(rl[2])),
            rv[0].Negate().Mul(ch_beta_inv),
            f_[4].Mul(ch_beta_inv).Add(delta.Mul(ro[5])).Add(rr[3].Sub(rl[4])),
            f_[5].Mul(ch_beta_inv).Add(rr[4].Add(delta.Mul(ro[6])).Sub(rl[5])),
            f_[6].Mul(ch_beta_inv).Add(delta.Mul(ro[7]).Sub(rl[6]).Add(rr[5]))
        };

        var Cs = VectorPointScalarMul(pub.HVec, rs.Concat(ls).ToArray(), group);
        Cs = Cs.Add(VectorPointScalarMul(pub.GVec, ns, group));

        proof.CS = Cs;

        fs.AddPoint(Cs);

        var t = fs.GetChallenge(group);
        var tinv = t.Inv();
        var t2 = t.Mul(t);
        var t3 = t2.Mul(t);

        var lT = VectorMulOnScalar(rs.Concat(ls).ToArray(), tinv);
        lT = VectorSub(lT, VectorMulOnScalar(ro.Concat(lo).ToArray(), delta), group);
        lT = VectorAdd(lT, VectorMulOnScalar(rl.Concat(ll).ToArray(), t), group);
        lT = VectorSub(lT, VectorMulOnScalar(rr.Concat(lr).ToArray(), t2), group);
        lT = VectorAdd(lT, VectorMulOnScalar(rv.Concat(v_1).ToArray(), t3), group);

        var pnT = VectorMulOnScalar(cnO, dinv.Mul(t3));
        pnT = VectorSub(pnT, VectorMulOnScalar(cnL, t2), group);
        pnT = VectorAdd(pnT, VectorMulOnScalar(cnR, t), group);

        var psT = WeightVectorMul(pnT, pnT, mu, group);
        psT = psT.Add(two.Mul(VectorMul(lambdaVec, pub.Al, group).Mul(t3)));
        psT = psT.Sub(two.Mul(VectorMul(muVec, pub.Am, group).Mul(t3)));

        var n_T = VectorMulOnScalar(ns, tinv);
        n_T = VectorSub(n_T, VectorMulOnScalar(no, delta), group);
        n_T = VectorAdd(n_T, VectorMulOnScalar(nl, t), group);
        n_T = VectorSub(n_T, VectorMulOnScalar(nr, t2), group);

        var nT = VectorAdd(pnT, n_T, group);

        var cr_T = BuildCrT(beta, tinv, t, t2, t3, group);

        var cl_T = VectorMulOnScalar(clO, t3.Mul(dinv));
        cl_T = VectorSub(cl_T, VectorMulOnScalar(clL, t2), group);
        cl_T = VectorAdd(cl_T, VectorMulOnScalar(clR, t), group);
        cl_T = VectorMulOnScalar(cl_T, two);
        cl_T = VectorSub(cl_T, cl0, group);

        var cT = cr_T.Concat(cl_T).ToArray();

        var vT = psT.Add(v_.Mul(t3));

        var CT = pub.G.ScalarMul(vT);
        CT = CT.Add(VectorPointScalarMul(pub.HVec, lT, group));
        CT = CT.Add(VectorPointScalarMul(pub.GVec, nT, group));

        // Extend vectors with zeros up to 2^i
        var totalH = pub.HVec.Length + pub.HVec_.Length;
        var totalG = pub.GVec.Length + pub.GVec_.Length;

        while (lT.Length < totalH)
        {
            lT = lT.Concat(new[] { zero }).ToArray();
            cT = cT.Concat(new[] { zero }).ToArray();
        }

        while (nT.Length < totalG)
            nT = nT.Concat(new[] { zero }).ToArray();

        proof.WNLA = Wnla.ProveWnla(
            new WeightNormLinearPublic
            {
                G = pub.G,
                GVec = pub.GVec.Concat(pub.GVec_).ToArray(),
                HVec = pub.HVec.Concat(pub.HVec_).ToArray(),
                C = cT,
                Ro = rho,
                Mu = mu
            },
            CT, fs, lT, nT, group);

        return proof;
    }

    // ─── Shared helpers ───

    private static IScalar[] CalculateLambdaVec(ArithmeticCircuitPublic pub, IScalar lambda, IScalar mu, IGroup group)
    {
        var lambdaVec = VectorAdd(
            VectorTensorMul(VectorMulOnScalar(E(lambda, pub.Nv, group), mu), E(group.Pow(mu, pub.Nv), pub.K, group)),
            VectorTensorMul(E(mu, pub.Nv, group), E(group.Pow(lambda, pub.Nv), pub.K, group)),
            group);

        lambdaVec = VectorMulOnScalar(lambdaVec, group.ScalarFromInt(pub.Fl && pub.Fm ? 1 : 0));
        lambdaVec = VectorSub(E(lambda, pub.Nl, group), lambdaVec, group);
        return lambdaVec;
    }

    private static IScalar[] CalculateCl0(ArithmeticCircuitPublic pub, IScalar lambda, IScalar mu, IGroup group)
    {
        var fl = group.ScalarFromInt(pub.Fl ? 1 : 0);
        var fm = group.ScalarFromInt(pub.Fm ? 1 : 0);

        return VectorSub(
            VectorMulOnScalar(E(lambda, pub.Nv, group)[1..], fl),
            VectorMulOnScalar(VectorMulOnScalar(E(mu, pub.Nv, group)[1..], mu), fm),
            group);
    }

    private static IScalar[] BuildCrT(IScalar beta, IScalar tinv, IScalar t, IScalar t2, IScalar t3, IGroup group)
    {
        return new IScalar[]
        {
            group.ScalarFromInt(1),
            beta.Mul(tinv),
            beta.Mul(t),
            beta.Mul(t2),
            beta.Mul(t3),
            beta.Mul(t.Mul(t3)),
            beta.Mul(t2.Mul(t3)),
            beta.Mul(t3.Mul(t3)),
            beta.Mul(t3.Mul(t).Mul(t3))
        };
    }

    private static (IScalar[][] MlnL, IScalar[][] MmnL, IScalar[][] MlnR, IScalar[][] MmnR)
        CalculateMRL(ArithmeticCircuitPublic pub)
    {
        var MlnL = new IScalar[pub.Nl][];
        for (int i = 0; i < pub.Nl; i++)
            MlnL[i] = pub.Wl[i][..pub.Nm];

        var MmnL = new IScalar[pub.Nm][];
        for (int i = 0; i < pub.Nm; i++)
            MmnL[i] = pub.Wm[i][..pub.Nm];

        var MlnR = new IScalar[pub.Nl][];
        for (int i = 0; i < pub.Nl; i++)
            MlnR[i] = pub.Wl[i][pub.Nm..(pub.Nm * 2)];

        var MmnR = new IScalar[pub.Nm][];
        for (int i = 0; i < pub.Nm; i++)
            MmnR[i] = pub.Wm[i][pub.Nm..(pub.Nm * 2)];

        return (MlnL, MmnL, MlnR, MmnR);
    }

    private static (IScalar[][] MlnO, IScalar[][] MmnO,
        IScalar[][] MllL, IScalar[][] MmlL,
        IScalar[][] MllR, IScalar[][] MmlR,
        IScalar[][] MllO, IScalar[][] MmlO)
        CalculateMO(ArithmeticCircuitPublic pub, IGroup group)
    {
        var zero = group.ScalarFromInt(0);

        var WlO = new IScalar[pub.Nl][];
        for (int i = 0; i < pub.Nl; i++)
            WlO[i] = pub.Wl[i][(pub.Nm * 2)..];

        var WmO = new IScalar[pub.Nm][];
        for (int i = 0; i < pub.Nm; i++)
            WmO[i] = pub.Wm[i][(pub.Nm * 2)..];

        IScalar[][] BuildNMatrix(int rows, IScalar[][] wO, PartitionType pType)
        {
            var res = new IScalar[rows][];
            for (int i = 0; i < rows; i++)
            {
                res[i] = new IScalar[pub.Nm];
                for (int j = 0; j < pub.Nm; j++)
                {
                    res[i][j] = zero;
                    var idx = pub.F(pType, j);
                    if (idx.HasValue) res[i][j] = wO[i][idx.Value];
                }
            }
            return res;
        }

        IScalar[][] BuildLMatrix(int rows, IScalar[][] wO, PartitionType pType)
        {
            var res = new IScalar[rows][];
            for (int i = 0; i < rows; i++)
            {
                res[i] = new IScalar[pub.Nv];
                for (int j = 0; j < pub.Nv; j++)
                {
                    res[i][j] = zero;
                    var idx = pub.F(pType, j);
                    if (idx.HasValue) res[i][j] = wO[i][idx.Value];
                }
            }
            return res;
        }

        return (
            BuildNMatrix(pub.Nl, WlO, PartitionType.NO),
            BuildNMatrix(pub.Nm, WmO, PartitionType.NO),
            BuildLMatrix(pub.Nl, WlO, PartitionType.LL),
            BuildLMatrix(pub.Nm, WmO, PartitionType.LL),
            BuildLMatrix(pub.Nl, WlO, PartitionType.LR),
            BuildLMatrix(pub.Nm, WmO, PartitionType.LR),
            BuildLMatrix(pub.Nl, WlO, PartitionType.LO),
            BuildLMatrix(pub.Nm, WmO, PartitionType.LO)
        );
    }
}
