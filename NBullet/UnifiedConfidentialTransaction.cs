namespace NBullet;

/// <summary>
/// Unified confidential transaction: produces one proof artifact per transaction that
/// proves (a) every output value is in [0, 2^64), (b) one-hot selection over inputs,
/// (c) actual asset-tag surjection via Schnorr 1-of-N, and (d) value conservation as
/// a point check. All sub-proofs share one Fiat-Shamir transcript bound to the public
/// inputs / outputs / excess.
///
/// Compared to <see cref="ConfidentialTransaction"/>, this variant ACTUALLY enforces
/// asset surjection. Prefer this API when asset-binding correctness matters.
/// </summary>
public static class UnifiedConfidentialTransaction
{
    public static UnifiedConfidentialTxProof Prove(
        ConfidentialTxInput[] inputs,
        ConfidentialTxOutput[] outputs,
        IPoint excess,
        ConfidentialTxWitness witness,
        Func<IFiatShamirEngine> makeFs,
        IGroup group)
    {
        int M = outputs.Length;
        int N = inputs.Length;

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

        var selections = new int[M][];
        for (int j = 0; j < M; j++)
        {
            selections[j] = new int[N];
            selections[j][witness.MatchingInputIndices[j]] = 1;
        }

        var selectFs = makeFs();
        AddTranscriptContext(selectFs, inputs, outputs, excess);
        selectFs.AddScalar(group.ScalarFromInt(-1));

        var (oneHotProof, oneHotComs) = SelectionProof.Prove(M, N, selections, selectFs, group);

        var surjectionProofs = new AssetSurjectionProof[M];
        var inputTags = new IPoint[N];
        for (int i = 0; i < N; i++) inputTags[i] = inputs[i].BlindedAssetTag;

        for (int j = 0; j < M; j++)
        {
            int k = witness.MatchingInputIndices[j];
            var d = witness.OutputAssetBlindingFactors[j].Sub(witness.InputAssetBlindingFactors[k]);

            var surjFs = makeFs();
            AddTranscriptContext(surjFs, inputs, outputs, excess);
            // Domain separator distinct from range (j ≥ 0) and selection (-1).
            surjFs.AddScalar(group.ScalarFromInt(-2 - j));

            surjectionProofs[j] = AssetSurjection.Prove(
                inputTags, outputs[j].BlindedAssetTag, k, d, surjFs, group);
        }

        return new UnifiedConfidentialTxProof
        {
            RangeProofs = rangeProofs,
            OneHotProof = oneHotProof,
            OneHotCommitments = oneHotComs,
            AssetSurjectionProofs = surjectionProofs
        };
    }

    public static string? Verify(
        ConfidentialTxInput[] inputs,
        ConfidentialTxOutput[] outputs,
        IPoint excess,
        UnifiedConfidentialTxProof proof,
        Func<IFiatShamirEngine> makeFs,
        IGroup group)
    {
        int M = outputs.Length;
        int N = inputs.Length;

        var conservationErr = VerifyConservation(inputs, outputs, excess, group);
        if (conservationErr != null) return conservationErr;

        if (proof.RangeProofs.Length != M) return "wrong number of range proofs";
        if (proof.AssetSurjectionProofs.Length != M) return "wrong number of asset surjection proofs";

        for (int j = 0; j < M; j++)
        {
            var pub = NumsGenerator.CreateDeterministicReciprocalPublic(16, 16, group);
            var fs = makeFs();
            AddTranscriptContext(fs, inputs, outputs, excess);
            fs.AddScalar(group.ScalarFromInt(j));

            var err = Reciprocal.VerifyRange(pub, outputs[j].ValueCommitment, fs, proof.RangeProofs[j], group);
            if (err != null) return $"range proof {j} failed: {err}";
        }

        var selectFs = makeFs();
        AddTranscriptContext(selectFs, inputs, outputs, excess);
        selectFs.AddScalar(group.ScalarFromInt(-1));

        var selectErr = SelectionProof.Verify(M, N, proof.OneHotCommitments, proof.OneHotProof, selectFs, group);
        if (selectErr != null) return $"one-hot selection failed: {selectErr}";

        var inputTags = new IPoint[N];
        for (int i = 0; i < N; i++) inputTags[i] = inputs[i].BlindedAssetTag;

        for (int j = 0; j < M; j++)
        {
            var surjFs = makeFs();
            AddTranscriptContext(surjFs, inputs, outputs, excess);
            surjFs.AddScalar(group.ScalarFromInt(-2 - j));

            var err = AssetSurjection.Verify(
                inputTags, outputs[j].BlindedAssetTag, proof.AssetSurjectionProofs[j], surjFs, group);
            if (err != null) return $"asset surjection {j} failed: {err}";
        }

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
