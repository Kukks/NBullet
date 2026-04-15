using static NBullet.VectorMath;

namespace NBullet;

/// <summary>
/// One-hot selection proof: proves that for each of K groups, exactly one of N binary
/// variables is 1. Built on the arithmetic circuit protocol with binary + summation constraints.
/// </summary>
public static class SelectionProof
{
    public static (ArithmeticCircuitProof proof, IPoint[] commitments) Prove(
        int K, int N, int[][] selections,
        IFiatShamirEngine fs, IGroup group)
    {
        int Nm = K * N;
        int No = 0;
        int Nv = 1;
        int Nl = Nv;
        int Nw = 2 * Nm;

        var wlArr = new IScalar[Nm];
        var wrArr = new IScalar[Nm];
        var vArr = new IScalar[K][];
        var svArr = new IScalar[K];

        for (int k = 0; k < K; k++)
        {
            for (int i = 0; i < N; i++)
            {
                var val = group.ScalarFromInt(selections[k][i]);
                wlArr[k * N + i] = val;
                wrArr[k * N + i] = val;
            }
            vArr[k] = new[] { group.ScalarFromInt(0) };
            svArr[k] = group.RandomScalar();
        }

        var pub = BuildCircuit(K, N, Nm, Nl, Nv, Nw, No, group);

        var priv = new ArithmeticCircuitPrivate
        {
            V = vArr, Sv = svArr,
            Wl = wlArr, Wr = wrArr, Wo = Array.Empty<IScalar>()
        };

        var V = new IPoint[K];
        for (int i = 0; i < K; i++)
            V[i] = ArithmeticCircuit.CommitCircuit(pub, priv.V[i], priv.Sv[i], group);

        var proof = ArithmeticCircuit.ProveCircuit(pub, V, fs, priv, group);
        return (proof, V);
    }

    public static string? Verify(
        int K, int N, IPoint[] commitments,
        ArithmeticCircuitProof proof, IFiatShamirEngine fs, IGroup group)
    {
        int Nm = K * N;
        int No = 0;
        int Nv = 1;
        int Nl = Nv;
        int Nw = 2 * Nm;

        var pub = BuildCircuit(K, N, Nm, Nl, Nv, Nw, No, group);

        return ArithmeticCircuit.VerifyCircuit(pub, commitments, fs, proof, group);
    }

    private static ArithmeticCircuitPublic BuildCircuit(
        int K, int N, int Nm, int Nl, int Nv, int Nw, int No, IGroup group)
    {
        var Am = ZeroVector(group, Nm);
        var Wm = ZeroMatrix(group, Nm, Nw);
        for (int idx = 0; idx < Nm; idx++)
            Wm[idx][idx] = group.ScalarFromInt(1);

        var Al = ZeroVector(group, Nl * K);
        var Wl = ZeroMatrix(group, Nl * K, Nw);
        for (int k = 0; k < K; k++)
        {
            Al[k] = group.ScalarFromInt(-1);
            for (int i = 0; i < N; i++)
                Wl[k][k * N + i] = group.ScalarFromInt(1);
        }

        int totalG = PowerOfTwo(Nm);
        int totalH = PowerOfTwo(9 + Nv);

        var gvec = NumsGenerator.DeterministicGenerators("NBullet.Sel.GVec", totalG, group);
        var hvec = NumsGenerator.DeterministicGenerators("NBullet.Sel.HVec", totalH, group);

        var pub = new ArithmeticCircuitPublic
        {
            Nm = Nm, Nl = Nl, Nv = Nv, Nw = Nw, No = No, K = K,
            G = NumsGenerator.StandardH(group),
            GVec = gvec[..Nm],
            HVec = hvec[..(9 + Nv)],
            Wm = Wm, Wl = Wl, Am = Am, Al = Al,
            Fl = true, Fm = false,
            F = (_, _) => null,
            GVec_ = gvec[Nm..],
            HVec_ = hvec[(9 + Nv)..]
        };

        return pub;
    }
}
