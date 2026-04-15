using static NBullet.VectorMath;

namespace NBullet;

/// <summary>
/// Unified range + surjection + conservation proof for confidential transactions.
/// Combines BP++ reciprocal range proofs with an arithmetic circuit surjection proof.
/// Surjection soundness: binary one-hot selection + conservation + NUMS assumption.
/// </summary>
public static class ConfidentialTransaction
{
    public static IPoint CommitValue(IPoint valueBase, IScalar value, IScalar blinding, IPoint blindingBase)
    {
        return valueBase.ScalarMul(value).Add(blindingBase.ScalarMul(blinding));
    }

    public static IPoint BlindAssetTag(IPoint assetGenerator, IScalar blinding, IGroup group)
    {
        return assetGenerator.Add(group.Generator.ScalarMul(blinding));
    }

    public static ConfidentialTxProof Prove(
        ConfidentialTxInput[] inputs,
        ConfidentialTxOutput[] outputs,
        IPoint excess,
        ConfidentialTxWitness witness,
        Func<IFiatShamirEngine> makeFs,
        IGroup group)
    {
        int M = outputs.Length;

        var rangeProofs = new ReciprocalProof[M];

        for (int j = 0; j < M; j++)
        {
            var pub = NumsGenerator.CreateDeterministicReciprocalPublic(16, 16, group);
            var value = witness.OutputValues[j];
            var x = group.ScalarFromBigInteger(new System.Numerics.BigInteger(value));
            var digits = NumberUtils.UInt64Hex(value, group);
            var m = NumberUtils.HexMapping(digits, group);
            var s = witness.OutputValueBlindingFactors[j];

            var priv = new ReciprocalPrivate { X = x, M = m, Digits = digits, S = s };

            var fs = makeFs();
            AddTranscriptContext(fs, inputs, outputs, excess);
            fs.AddScalar(group.ScalarFromInt(j));

            rangeProofs[j] = Reciprocal.ProveRange(pub, fs, priv, group);
        }

        var (surjectionProof, surjectionComs) =
            ProveSurjection(inputs, outputs, witness, makeFs(), excess, group);

        return new ConfidentialTxProof
        {
            RangeProofs = rangeProofs,
            SurjectionProof = surjectionProof,
            SurjectionCommitments = surjectionComs
        };
    }

    public static string? Verify(
        ConfidentialTxInput[] inputs,
        ConfidentialTxOutput[] outputs,
        IPoint excess,
        ConfidentialTxProof proof,
        Func<IFiatShamirEngine> makeFs,
        IGroup group)
    {
        int M = outputs.Length;

        var conservationErr = VerifyConservation(inputs, outputs, excess, group);
        if (conservationErr != null) return conservationErr;

        if (proof.RangeProofs.Length != M)
            return "wrong number of range proofs";

        for (int j = 0; j < M; j++)
        {
            var pub = NumsGenerator.CreateDeterministicReciprocalPublic(16, 16, group);
            var vCom = outputs[j].ValueCommitment;

            var fs = makeFs();
            AddTranscriptContext(fs, inputs, outputs, excess);
            fs.AddScalar(group.ScalarFromInt(j));

            var err = Reciprocal.VerifyRange(pub, vCom, fs, proof.RangeProofs[j], group);
            if (err != null) return $"range proof {j} failed: {err}";
        }

        var surjErr = VerifySurjection(inputs, outputs, proof, makeFs(), excess, group);
        if (surjErr != null) return surjErr;

        return null;
    }

    private static string? VerifyConservation(
        ConfidentialTxInput[] inputs, ConfidentialTxOutput[] outputs,
        IPoint excess, IGroup group)
    {
        var negOne = group.ScalarFromInt(-1);
        var balance = group.Infinity;

        foreach (var o in outputs)
            balance = balance.Add(o.ValueCommitment);
        foreach (var i in inputs)
            balance = balance.Add(i.ValueCommitment.ScalarMul(negOne));

        balance = balance.Add(excess.ScalarMul(negOne));

        if (!balance.IsInfinity)
            return "conservation failed: sum(outputs) - sum(inputs) != excess";

        return null;
    }

    private static (ArithmeticCircuitProof proof, IPoint[] commitments) ProveSurjection(
        ConfidentialTxInput[] inputs, ConfidentialTxOutput[] outputs,
        ConfidentialTxWitness witness, IFiatShamirEngine fs,
        IPoint excess, IGroup group)
    {
        int M = outputs.Length;
        int N = inputs.Length;

        AddTranscriptContext(fs, inputs, outputs, excess);
        fs.AddScalar(group.ScalarFromInt(-1));

        var selections = new IScalar[M][];
        for (int j = 0; j < M; j++)
        {
            selections[j] = ZeroVector(group, N);
            selections[j][witness.MatchingInputIndices[j]] = group.ScalarFromInt(1);
        }

        int Nm = M * N;
        int No = 0;
        int Nv = 1;
        int Nl = Nv;
        int Nw = 2 * Nm;
        int K = M;

        var wlArr = new IScalar[Nm];
        var wrArr = new IScalar[Nm];

        var vArr = new IScalar[M][];
        var svArr = new IScalar[M];

        for (int j = 0; j < M; j++)
        {
            for (int i = 0; i < N; i++)
            {
                wlArr[j * N + i] = selections[j][i];
                wrArr[j * N + i] = selections[j][i];
            }
            vArr[j] = new[] { group.ScalarFromInt(0) };
            svArr[j] = group.RandomScalar();
        }

        var Am = ZeroVector(group, Nm);
        var Wm = ZeroMatrix(group, Nm, Nw);
        for (int idx = 0; idx < Nm; idx++)
            Wm[idx][idx] = group.ScalarFromInt(1);

        var Al = ZeroVector(group, Nl * K);
        var Wl = ZeroMatrix(group, Nl * K, Nw);
        for (int j = 0; j < M; j++)
        {
            Al[j] = group.ScalarFromInt(-1);
            for (int i = 0; i < N; i++)
                Wl[j][j * N + i] = group.ScalarFromInt(1);
        }

        int totalG = PowerOfTwo(Nm);
        int totalH = PowerOfTwo(9 + Nv);

        var gvec = NumsGenerator.DeterministicGenerators("NBullet.Surj.GVec", totalG, group);
        var hvec = NumsGenerator.DeterministicGenerators("NBullet.Surj.HVec", totalH, group);

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

    private static string? VerifySurjection(
        ConfidentialTxInput[] inputs, ConfidentialTxOutput[] outputs,
        ConfidentialTxProof proof, IFiatShamirEngine fs,
        IPoint excess, IGroup group)
    {
        if (proof.SurjectionProof == null)
            return "missing surjection proof";

        int M = outputs.Length;
        int N = inputs.Length;

        AddTranscriptContext(fs, inputs, outputs, excess);
        fs.AddScalar(group.ScalarFromInt(-1));

        int Nm = M * N;
        int No = 0;
        int Nv = 1;
        int Nl = Nv;
        int Nw = 2 * Nm;
        int K = M;

        var Am = ZeroVector(group, Nm);
        var Wm = ZeroMatrix(group, Nm, Nw);
        for (int idx = 0; idx < Nm; idx++)
            Wm[idx][idx] = group.ScalarFromInt(1);

        var Al = ZeroVector(group, Nl * K);
        var Wl = ZeroMatrix(group, Nl * K, Nw);
        for (int j = 0; j < M; j++)
        {
            Al[j] = group.ScalarFromInt(-1);
            for (int i = 0; i < N; i++)
                Wl[j][j * N + i] = group.ScalarFromInt(1);
        }

        int totalG = PowerOfTwo(Nm);
        int totalH = PowerOfTwo(9 + Nv);

        var gvec = NumsGenerator.DeterministicGenerators("NBullet.Surj.GVec", totalG, group);
        var hvec = NumsGenerator.DeterministicGenerators("NBullet.Surj.HVec", totalH, group);

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

        return ArithmeticCircuit.VerifyCircuit(pub, proof.SurjectionCommitments, fs,
            proof.SurjectionProof, group);
    }

    private static void AddTranscriptContext(
        IFiatShamirEngine fs,
        ConfidentialTxInput[] inputs, ConfidentialTxOutput[] outputs, IPoint excess)
    {
        foreach (var inp in inputs)
        {
            fs.AddPoint(inp.ValueCommitment);
            fs.AddPoint(inp.BlindedAssetTag);
        }
        foreach (var outp in outputs)
        {
            fs.AddPoint(outp.ValueCommitment);
            fs.AddPoint(outp.BlindedAssetTag);
        }
        fs.AddPoint(excess);
    }
}
