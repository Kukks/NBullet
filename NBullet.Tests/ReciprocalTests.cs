using NBullet;
using NBullet.BouncyCastle;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class ReciprocalTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Fact]
    public void TestReciprocalRangeProofUInt64()
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

        var proof = Reciprocal.ProveRange(pub, new KeccakFiatShamirEngine(), priv, _group);
        var err = Reciprocal.VerifyRange(pub, vCom, new KeccakFiatShamirEngine(), proof, _group);

        Assert.Null(err);
    }
}
