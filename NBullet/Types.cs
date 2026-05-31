namespace NBullet;

// ─── WNLA types ───

public class WeightNormLinearPublic
{
    public required IPoint G { get; init; }
    public required IPoint[] GVec { get; init; }
    public required IPoint[] HVec { get; init; }
    public required IScalar[] C { get; init; }
    public required IScalar Ro { get; init; }
    public required IScalar Mu { get; init; }
}

public class WeightNormLinearArgumentProof
{
    public required IPoint[] R { get; init; }
    public required IPoint[] X { get; init; }
    public required IScalar[] L { get; init; }
    public required IScalar[] N { get; init; }
}

// ─── Arithmetic circuit types ───

public enum PartitionType { LO, LL, LR, NO }

public delegate int? PartitionFunc(PartitionType typ, int index);

public class ArithmeticCircuitPublic
{
    public required int Nm { get; init; }
    public required int Nl { get; init; }
    public required int Nv { get; init; }
    public required int Nw { get; init; }
    public required int No { get; init; }
    public required int K { get; init; }
    public required IPoint G { get; init; }
    public required IPoint[] GVec { get; init; }
    public required IPoint[] HVec { get; init; }
    public required IScalar[][] Wm { get; init; }
    public required IScalar[][] Wl { get; init; }
    public required IScalar[] Am { get; init; }
    public required IScalar[] Al { get; init; }
    public required bool Fl { get; init; }
    public required bool Fm { get; init; }
    public required PartitionFunc F { get; init; }
    public required IPoint[] GVec_ { get; init; }
    public required IPoint[] HVec_ { get; init; }
}

public class ArithmeticCircuitPrivate
{
    public required IScalar[][] V { get; init; }
    public required IScalar[] Sv { get; init; }
    public required IScalar[] Wl { get; init; }
    public required IScalar[] Wr { get; init; }
    public required IScalar[] Wo { get; init; }
}

public class ArithmeticCircuitProof
{
    public required IPoint CL { get; init; }
    public required IPoint CR { get; init; }
    public required IPoint CO { get; init; }
    public IPoint? CS { get; set; }
    public WeightNormLinearArgumentProof? WNLA { get; set; }
}

// ─── Confidential Transaction types ───

public class ConfidentialTxInput
{
    public required IPoint ValueCommitment { get; init; }
    public required IPoint BlindedAssetTag { get; init; }
}

public class ConfidentialTxOutput
{
    public required IPoint ValueCommitment { get; init; }
    public required IPoint BlindedAssetTag { get; init; }
}

public class ConfidentialTxWitness
{
    public required ulong[] OutputValues { get; init; }
    public required IScalar[] OutputValueBlindingFactors { get; init; }
    public required IScalar[] InputAssetBlindingFactors { get; init; }
    public required IScalar[] OutputAssetBlindingFactors { get; init; }
    public required int[] MatchingInputIndices { get; init; }
}

public class ConfidentialTxProof
{
    public required ReciprocalProof[] RangeProofs { get; init; }
    public required ArithmeticCircuitProof? SurjectionProof { get; init; }
    public required IPoint[] SurjectionCommitments { get; init; }
}

// ─── Reciprocal range proof types ───

public class ReciprocalPublic
{
    public required IPoint G { get; init; }
    public required IPoint[] GVec { get; init; }
    public required IPoint[] HVec { get; init; }
    public required int Nd { get; init; }
    public required int Np { get; init; }
    public required IPoint[] GVec_ { get; init; }
    public required IPoint[] HVec_ { get; init; }
}

public class ReciprocalPrivate
{
    public required IScalar X { get; init; }
    public required IScalar[] M { get; init; }
    public required IScalar[] Digits { get; init; }
    public required IScalar S { get; init; }
}

public class ReciprocalProof
{
    public required ArithmeticCircuitProof CircuitProof { get; init; }
    public required IPoint V { get; init; }
}

// ─── Asset surjection types ───

/// <summary>
/// Schnorr 1-of-N OR-proof that <c>outputAssetTag - inputAssetTags[k] = d * G</c>
/// for some hidden index k and scalar d.
/// Compressed form: only (e_i, s_i) per branch — verifier reconstructs the commitments.
/// </summary>
public class AssetSurjectionProof
{
    public required IScalar[] Challenges { get; init; }   // length N
    public required IScalar[] Responses { get; init; }    // length N
}

// ─── Unified confidential transaction types ───

/// <summary>
/// Combined proof artifact for <see cref="UnifiedConfidentialTransaction"/>:
/// bundles per-output range proofs, a single one-hot selection proof, and
/// per-output Schnorr 1-of-N asset surjection proofs.
/// </summary>
public class UnifiedConfidentialTxProof
{
    public required ReciprocalProof[] RangeProofs { get; init; }                  // length M
    public required ArithmeticCircuitProof OneHotProof { get; init; }
    public required IPoint[] OneHotCommitments { get; init; }                     // length M
    public required AssetSurjectionProof[] AssetSurjectionProofs { get; init; }   // length M
}
