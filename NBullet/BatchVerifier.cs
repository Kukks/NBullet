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
