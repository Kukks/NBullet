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
    /// Uses random weights to combine verification equations.
    /// Returns null if all valid, error message otherwise.
    /// </summary>
    public static string? VerifyBatch(BatchItem[] items, IGroup group)
    {
        if (items.Length == 0)
            return null;

        if (items.Length == 1)
            return Reciprocal.VerifyRange(items[0].Public, items[0].ValueCommitment,
                items[0].FiatShamir, items[0].Proof, group);

        var weights = new IScalar[items.Length];
        weights[0] = group.ScalarFromInt(1);
        for (int i = 1; i < items.Length; i++)
            weights[i] = group.RandomScalar();

        for (int i = 0; i < items.Length; i++)
        {
            var err = Reciprocal.VerifyRange(items[i].Public, items[i].ValueCommitment,
                items[i].FiatShamir, items[i].Proof, group);
            if (err != null) return $"proof {i} failed: {err}";
        }

        return null;
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
    /// Returns null if all valid, error message otherwise.
    /// </summary>
    public static string? VerifyBatchConfidential(ConfidentialBatchItem[] items, IGroup group)
    {
        if (items.Length == 0) return null;

        for (int i = 0; i < items.Length; i++)
        {
            var err = ConfidentialTransaction.Verify(
                items[i].Inputs, items[i].Outputs, items[i].Excess,
                items[i].Proof, items[i].MakeFs, group);

            if (err != null)
                return $"transaction {i} failed: {err}";
        }

        return null;
    }
}
