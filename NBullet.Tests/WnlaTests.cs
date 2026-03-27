using NBullet;
using NBullet.BouncyCastle;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class WnlaTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Fact]
    public void TestWNLA_Keccak()
    {
        var pub = Wnla.NewWeightNormLinearPublic(8, 4, _group);

        var l = new IScalar[]
        {
            _group.ScalarFromInt(4), _group.ScalarFromInt(5),
            _group.ScalarFromInt(10), _group.ScalarFromInt(1),
            _group.ScalarFromInt(99), _group.ScalarFromInt(35),
            _group.ScalarFromInt(1), _group.ScalarFromInt(15)
        };
        var n = new IScalar[]
        {
            _group.ScalarFromInt(1), _group.ScalarFromInt(3),
            _group.ScalarFromInt(42), _group.ScalarFromInt(14)
        };

        var com = Wnla.CommitWnla(pub, l, n, _group);
        var proof = Wnla.ProveWnla(pub, com, new KeccakFiatShamirEngine(), l, n, _group);

        var com2 = Wnla.CommitWnla(pub, l, n, _group);
        var err = Wnla.VerifyWnla(pub, proof, com2, new KeccakFiatShamirEngine(), _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestWNLA_Sha256()
    {
        var pub = Wnla.NewWeightNormLinearPublic(8, 4, _group);

        var l = new IScalar[]
        {
            _group.ScalarFromInt(4), _group.ScalarFromInt(5),
            _group.ScalarFromInt(10), _group.ScalarFromInt(1),
            _group.ScalarFromInt(99), _group.ScalarFromInt(35),
            _group.ScalarFromInt(1), _group.ScalarFromInt(15)
        };
        var n = new IScalar[]
        {
            _group.ScalarFromInt(1), _group.ScalarFromInt(3),
            _group.ScalarFromInt(42), _group.ScalarFromInt(14)
        };

        var com = Wnla.CommitWnla(pub, l, n, _group);
        var proof = Wnla.ProveWnla(pub, com, new Sha256FiatShamirEngine(), l, n, _group);

        var com2 = Wnla.CommitWnla(pub, l, n, _group);
        var err = Wnla.VerifyWnla(pub, proof, com2, new Sha256FiatShamirEngine(), _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestWNLA_WrongVectors_Fails()
    {
        var pub = Wnla.NewWeightNormLinearPublic(8, 4, _group);

        var l = new IScalar[]
        {
            _group.ScalarFromInt(4), _group.ScalarFromInt(5),
            _group.ScalarFromInt(10), _group.ScalarFromInt(1),
            _group.ScalarFromInt(99), _group.ScalarFromInt(35),
            _group.ScalarFromInt(1), _group.ScalarFromInt(15)
        };
        var n = new IScalar[]
        {
            _group.ScalarFromInt(1), _group.ScalarFromInt(3),
            _group.ScalarFromInt(42), _group.ScalarFromInt(14)
        };

        var com = Wnla.CommitWnla(pub, l, n, _group);
        var proof = Wnla.ProveWnla(pub, com, new KeccakFiatShamirEngine(), l, n, _group);

        // Verify against a DIFFERENT commitment (wrong l vector)
        var wrongL = new IScalar[]
        {
            _group.ScalarFromInt(99), _group.ScalarFromInt(5),
            _group.ScalarFromInt(10), _group.ScalarFromInt(1),
            _group.ScalarFromInt(99), _group.ScalarFromInt(35),
            _group.ScalarFromInt(1), _group.ScalarFromInt(15)
        };
        var wrongCom = Wnla.CommitWnla(pub, wrongL, n, _group);
        var err = Wnla.VerifyWnla(pub, proof, wrongCom, new KeccakFiatShamirEngine(), _group);

        Assert.NotNull(err);
    }
}
