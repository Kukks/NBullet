using NBullet;
using NBullet.BouncyCastle;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class ReciprocalTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Theory]
    [InlineData(true)]  // Keccak
    [InlineData(false)] // SHA-256
    public void TestReciprocalRangeProofUInt64(bool useKeccak)
    {
        // uint64 in 16-base system will be encoded in 16 digits
        ulong x = 0xab4f0540ab4f0540;
        var X = _group.ScalarFromBigInteger(new System.Numerics.BigInteger(x));

        var digits = NumberUtils.UInt64Hex(x, _group);
        var m = NumberUtils.HexMapping(digits, _group);

        int Nd = 16; // digits size
        int Np = 16; // base size

        var wnlaPublic = Wnla.NewWeightNormLinearPublic(32, 16, _group);

        var pub = new ReciprocalPublic
        {
            G = wnlaPublic.G,
            GVec = wnlaPublic.GVec[..Nd],
            HVec = wnlaPublic.HVec[..(Nd + 1 + 9)],
            Nd = Nd, Np = Np,
            GVec_ = wnlaPublic.GVec[Nd..],
            HVec_ = wnlaPublic.HVec[(Nd + 1 + 9)..]
        };

        var priv = new ReciprocalPrivate
        {
            X = X,
            M = m,
            Digits = digits,
            S = _group.RandomScalar()
        };

        var vCom = Reciprocal.CommitValue(pub, priv.X, priv.S);

        IFiatShamirEngine MakeFs() => useKeccak ? new KeccakFiatShamirEngine() : new Sha256FiatShamirEngine();

        var proof = Reciprocal.ProveRange(pub, MakeFs(), priv, _group);
        var err = Reciprocal.VerifyRange(pub, vCom, MakeFs(), proof, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestReciprocalRangeProof_SmallValue()
    {
        // Test with a small value (edge case: value = 0)
        ulong x = 0;
        var X = _group.ScalarFromBigInteger(new System.Numerics.BigInteger(x));

        var digits = NumberUtils.UInt64Hex(x, _group);
        var m = NumberUtils.HexMapping(digits, _group);

        int Nd = 16;
        int Np = 16;

        var wnlaPublic = Wnla.NewWeightNormLinearPublic(32, 16, _group);

        var pub = new ReciprocalPublic
        {
            G = wnlaPublic.G,
            GVec = wnlaPublic.GVec[..Nd],
            HVec = wnlaPublic.HVec[..(Nd + 1 + 9)],
            Nd = Nd, Np = Np,
            GVec_ = wnlaPublic.GVec[Nd..],
            HVec_ = wnlaPublic.HVec[(Nd + 1 + 9)..]
        };

        var priv = new ReciprocalPrivate
        {
            X = X, M = m, Digits = digits,
            S = _group.RandomScalar()
        };

        var vCom = Reciprocal.CommitValue(pub, priv.X, priv.S);
        var proof = Reciprocal.ProveRange(pub, new Sha256FiatShamirEngine(), priv, _group);
        var err = Reciprocal.VerifyRange(pub, vCom, new Sha256FiatShamirEngine(), proof, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestReciprocalRangeProof_MaxValue()
    {
        // Test with max uint64 value
        ulong x = ulong.MaxValue;
        var X = _group.ScalarFromBigInteger(new System.Numerics.BigInteger(x));

        var digits = NumberUtils.UInt64Hex(x, _group);
        var m = NumberUtils.HexMapping(digits, _group);

        int Nd = 16;
        int Np = 16;

        var wnlaPublic = Wnla.NewWeightNormLinearPublic(32, 16, _group);

        var pub = new ReciprocalPublic
        {
            G = wnlaPublic.G,
            GVec = wnlaPublic.GVec[..Nd],
            HVec = wnlaPublic.HVec[..(Nd + 1 + 9)],
            Nd = Nd, Np = Np,
            GVec_ = wnlaPublic.GVec[Nd..],
            HVec_ = wnlaPublic.HVec[(Nd + 1 + 9)..]
        };

        var priv = new ReciprocalPrivate
        {
            X = X, M = m, Digits = digits,
            S = _group.RandomScalar()
        };

        var vCom = Reciprocal.CommitValue(pub, priv.X, priv.S);
        var proof = Reciprocal.ProveRange(pub, new Sha256FiatShamirEngine(), priv, _group);
        var err = Reciprocal.VerifyRange(pub, vCom, new Sha256FiatShamirEngine(), proof, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestReciprocalRangeProof_WrongCommitment_Fails()
    {
        ulong x = 0xab4f0540ab4f0540;
        var X = _group.ScalarFromBigInteger(new System.Numerics.BigInteger(x));

        var digits = NumberUtils.UInt64Hex(x, _group);
        var m = NumberUtils.HexMapping(digits, _group);

        int Nd = 16;
        int Np = 16;

        var wnlaPublic = Wnla.NewWeightNormLinearPublic(32, 16, _group);

        var pub = new ReciprocalPublic
        {
            G = wnlaPublic.G,
            GVec = wnlaPublic.GVec[..Nd],
            HVec = wnlaPublic.HVec[..(Nd + 1 + 9)],
            Nd = Nd, Np = Np,
            GVec_ = wnlaPublic.GVec[Nd..],
            HVec_ = wnlaPublic.HVec[(Nd + 1 + 9)..]
        };

        var priv = new ReciprocalPrivate
        {
            X = X, M = m, Digits = digits,
            S = _group.RandomScalar()
        };

        var vCom = Reciprocal.CommitValue(pub, priv.X, priv.S);
        var proof = Reciprocal.ProveRange(pub, new KeccakFiatShamirEngine(), priv, _group);

        // Verify with WRONG commitment (different value)
        var wrongX = _group.ScalarFromBigInteger(new System.Numerics.BigInteger(999));
        var wrongCom = Reciprocal.CommitValue(pub, wrongX, _group.RandomScalar());

        var err = Reciprocal.VerifyRange(pub, wrongCom, new KeccakFiatShamirEngine(), proof, _group);

        Assert.NotNull(err);
    }
}
