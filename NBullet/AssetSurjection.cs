namespace NBullet;

/// <summary>
/// Schnorr 1-of-N OR-proof for asset surjection. Proves there exists an index
/// k and a scalar d such that <c>outputAssetTag - inputAssetTags[k] = d * G</c>,
/// without revealing k or d.
///
/// Construction: Cramer-Damgård-Schoenmakers '94. Per branch i the proof carries
/// (e_i, s_i); the verifier reconstructs <c>T_i = s_i*G - e_i*(A_out - A_in_i)</c>.
/// Challenge <c>c = H(transcript, T_*)</c> must equal Σ e_i. At the true branch the
/// prover satisfies the Schnorr relation honestly; at the other branches the prover
/// simulates by picking e_i, s_i first and deriving T_i.
/// </summary>
public static class AssetSurjection
{
    public static AssetSurjectionProof Prove(
        IPoint[] inputAssetTags,
        IPoint outputAssetTag,
        int trueIndex,
        IScalar trueDifference,
        IFiatShamirEngine fs,
        IGroup group)
    {
        if (trueIndex < 0 || trueIndex >= inputAssetTags.Length)
            throw new ArgumentOutOfRangeException(nameof(trueIndex));

        int N = inputAssetTags.Length;
        var G = group.Generator;
        var negOne = group.ScalarFromInt(-1);

        var challenges = new IScalar[N];
        var responses = new IScalar[N];
        var commitments = new IPoint[N];

        var alpha = group.RandomScalar();

        // Simulate the non-true branches: pick (e_i, s_i) at random, derive T_i.
        for (int i = 0; i < N; i++)
        {
            if (i == trueIndex) continue;
            challenges[i] = group.RandomScalar();
            responses[i] = group.RandomScalar();
            var diffPoint = outputAssetTag.Add(inputAssetTags[i].ScalarMul(negOne));
            commitments[i] = G.ScalarMul(responses[i]).Add(diffPoint.ScalarMul(challenges[i].Negate()));
        }

        // True branch: T_k = alpha * G
        commitments[trueIndex] = G.ScalarMul(alpha);

        BindTranscript(fs, inputAssetTags, outputAssetTag, commitments);
        var challengeTotal = fs.GetChallenge(group);

        // e_k = c - Σ_{i≠k} e_i
        var sumOthers = group.ScalarFromInt(0);
        for (int i = 0; i < N; i++)
            if (i != trueIndex) sumOthers = sumOthers.Add(challenges[i]);
        challenges[trueIndex] = challengeTotal.Sub(sumOthers);

        // s_k = alpha + e_k * d
        responses[trueIndex] = alpha.Add(challenges[trueIndex].Mul(trueDifference));

        return new AssetSurjectionProof
        {
            Challenges = challenges,
            Responses = responses
        };
    }

    public static string? Verify(
        IPoint[] inputAssetTags,
        IPoint outputAssetTag,
        AssetSurjectionProof proof,
        IFiatShamirEngine fs,
        IGroup group)
    {
        int N = inputAssetTags.Length;
        if (proof.Challenges.Length != N) return "challenge vector length mismatch";
        if (proof.Responses.Length != N) return "response vector length mismatch";

        var G = group.Generator;
        var negOne = group.ScalarFromInt(-1);

        // Reconstruct T_i = s_i*G - e_i*(A_out - A_in_i)
        var commitments = new IPoint[N];
        for (int i = 0; i < N; i++)
        {
            var diffPoint = outputAssetTag.Add(inputAssetTags[i].ScalarMul(negOne));
            commitments[i] = G.ScalarMul(proof.Responses[i])
                .Add(diffPoint.ScalarMul(proof.Challenges[i].Negate()));
        }

        BindTranscript(fs, inputAssetTags, outputAssetTag, commitments);
        var expected = fs.GetChallenge(group);

        var sum = group.ScalarFromInt(0);
        for (int i = 0; i < N; i++)
            sum = sum.Add(proof.Challenges[i]);

        if (!sum.ToBytes().SequenceEqual(expected.ToBytes()))
            return "challenge sum does not match Fiat-Shamir challenge";

        return null;
    }

    private static void BindTranscript(
        IFiatShamirEngine fs,
        IPoint[] inputAssetTags,
        IPoint outputAssetTag,
        IPoint[] commitments)
    {
        foreach (var tag in inputAssetTags) fs.AddPoint(tag);
        fs.AddPoint(outputAssetTag);
        foreach (var c in commitments) fs.AddPoint(c);
    }
}
