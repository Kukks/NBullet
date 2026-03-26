namespace NBullet;

/// <summary>
/// Fiat-Shamir heuristic engine for non-interactive proof generation.
/// Absorbs points and scalars, produces deterministic challenges.
/// </summary>
public interface IFiatShamirEngine
{
    void AddPoint(IPoint p);
    void AddScalar(IScalar s);
    IScalar GetChallenge(IGroup group);
}
