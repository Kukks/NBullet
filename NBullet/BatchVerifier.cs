namespace NBullet;

/// <summary>
/// Batch verification for multiple independent BP++ proofs.
/// Uses randomized linear combination of verification equations for faster verification.
/// </summary>
public static class BatchVerifier
{
    /// <summary>
    /// A single proof with its public inputs for batch verification.
    /// </summary>
    public class BatchItem
    {
        public required ReciprocalPublic Public { get; init; }
        public required IPoint ValueCommitment { get; init; }
        public required ReciprocalProof Proof { get; init; }
        public required IFiatShamirEngine FiatShamir { get; init; }
    }

    /// <summary>
    /// Verify N independent range proofs faster than verifying individually.
    /// Folds each proof's verification equation into a shared MsmAccumulator with a
    /// random outer weight; one final point-equality check decides the entire batch.
    /// Returns null if all valid, error message otherwise.
    /// </summary>
    public static string? VerifyBatch(BatchItem[] items, IGroup group)
    {
        if (items.Length == 0)
            return null;

        var acc = new MsmAccumulator();

        for (int i = 0; i < items.Length; i++)
        {
            var weight = i == 0 ? group.ScalarFromInt(1) : group.RandomScalar();
            var err = Reciprocal.AccumulateRange(
                items[i].Public, items[i].ValueCommitment,
                items[i].FiatShamir, items[i].Proof, weight, acc, group);
            if (err != null) return $"proof {i} structural error: {err}";
        }

        return acc.Sum(group).IsInfinity ? null : "batch verification failed";
    }

    /// <summary>
    /// Batch-verify confidential transaction proofs.
    /// </summary>
    public class ConfidentialBatchItem
    {
        public required ConfidentialTxInput[] Inputs { get; init; }
        public required ConfidentialTxOutput[] Outputs { get; init; }
        public required IPoint Excess { get; init; }
        public required ConfidentialTxProof Proof { get; init; }
        public required Func<IFiatShamirEngine> MakeFs { get; init; }
    }

    /// <summary>
    /// Verify multiple independent confidential transaction proofs.
    /// Conservation checks run inline per transaction; range and selection sub-proofs
    /// are folded into a single shared MsmAccumulator with independent random weights.
    /// Returns null if all valid, error message otherwise.
    /// </summary>
    public static string? VerifyBatchConfidential(ConfidentialBatchItem[] items, IGroup group)
    {
        if (items.Length == 0) return null;

        var acc = new MsmAccumulator();

        for (int t = 0; t < items.Length; t++)
        {
            var item = items[t];
            int M = item.Outputs.Length;
            int N = item.Inputs.Length;

            // Conservation is a cheap independent check; do inline, early-return on failure.
            var conservationErr = VerifyConservation(item.Inputs, item.Outputs, item.Excess, group);
            if (conservationErr != null) return $"transaction {t}: {conservationErr}";

            if (item.Proof.RangeProofs.Length != M)
                return $"transaction {t}: wrong number of range proofs";

            // Each independent proof gets a fresh random weight to keep linear combinations sound.
            for (int j = 0; j < M; j++)
            {
                var rangeWeight = group.RandomScalar();
                var pub = NumsGenerator.CreateDeterministicReciprocalPublic(16, 16, group);

                var fs = item.MakeFs();
                AddConfidentialTranscriptContext(fs, item.Inputs, item.Outputs, item.Excess);
                fs.AddScalar(group.ScalarFromInt(j));

                var err = Reciprocal.AccumulateRange(
                    pub, item.Outputs[j].ValueCommitment, fs, item.Proof.RangeProofs[j],
                    rangeWeight, acc, group);
                if (err != null) return $"transaction {t} range proof {j}: {err}";
            }

            if (item.Proof.SurjectionProof == null)
                return $"transaction {t}: missing surjection proof";

            var selectionWeight = group.RandomScalar();
            var surjFs = item.MakeFs();
            AddConfidentialTranscriptContext(surjFs, item.Inputs, item.Outputs, item.Excess);
            surjFs.AddScalar(group.ScalarFromInt(-1));

            var surjErr = SelectionProof.AccumulateVerify(
                M, N, item.Proof.SurjectionCommitments, item.Proof.SurjectionProof,
                surjFs, selectionWeight, acc, group);
            if (surjErr != null) return $"transaction {t} surjection: {surjErr}";
        }

        return acc.Sum(group).IsInfinity ? null : "batch verification failed";
    }

    // Duplicated from ConfidentialTransaction so this file isn't coupled to its internals.
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

    private static void AddConfidentialTranscriptContext(
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
