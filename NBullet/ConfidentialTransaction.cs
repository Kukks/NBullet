using static NBullet.VectorMath;

namespace NBullet;

/// <summary>
/// Helper for confidential transactions combining BP++ range proofs with one-hot
/// selection proofs (surjection) and a conservation (balance) check.
/// Builds on the general-purpose SelectionProof, Reciprocal, and NumsGenerator primitives.
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

        int N = inputs.Length;
        var selections = new int[M][];
        for (int j = 0; j < M; j++)
        {
            selections[j] = new int[N];
            selections[j][witness.MatchingInputIndices[j]] = 1;
        }

        var surjFs = makeFs();
        AddTranscriptContext(surjFs, inputs, outputs, excess);
        surjFs.AddScalar(group.ScalarFromInt(-1));

        var (surjectionProof, surjectionComs) = SelectionProof.Prove(M, N, selections, surjFs, group);

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
        int N = inputs.Length;

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

        if (proof.SurjectionProof == null)
            return "missing surjection proof";

        var surjFs = makeFs();
        AddTranscriptContext(surjFs, inputs, outputs, excess);
        surjFs.AddScalar(group.ScalarFromInt(-1));

        var surjErr = SelectionProof.Verify(M, N, proof.SurjectionCommitments, proof.SurjectionProof, surjFs, group);
        if (surjErr != null) return $"surjection failed: {surjErr}";

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
