using NBullet;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class SelectionProofTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Fact]
    public void TestSingleGroupSingleElement()
    {
        var selections = new[] { new[] { 1 } };

        var (proof, coms) = SelectionProof.Prove(1, 1, selections,
            new Sha256FiatShamirEngine(), _group);

        var err = SelectionProof.Verify(1, 1, coms, proof,
            new Sha256FiatShamirEngine(), _group);
        Assert.Null(err);
    }

    [Fact]
    public void TestSingleGroupThreeElements()
    {
        var selections = new[] { new[] { 0, 1, 0 } };

        var (proof, coms) = SelectionProof.Prove(1, 3, selections,
            new Sha256FiatShamirEngine(), _group);

        var err = SelectionProof.Verify(1, 3, coms, proof,
            new Sha256FiatShamirEngine(), _group);
        Assert.Null(err);
    }

    [Fact]
    public void TestTwoGroupsFourElements()
    {
        var selections = new[]
        {
            new[] { 0, 0, 1, 0 },
            new[] { 1, 0, 0, 0 }
        };

        var (proof, coms) = SelectionProof.Prove(2, 4, selections,
            new Sha256FiatShamirEngine(), _group);

        var err = SelectionProof.Verify(2, 4, coms, proof,
            new Sha256FiatShamirEngine(), _group);
        Assert.Null(err);
    }

    [Fact]
    public void TestThreeGroupsTwoElements()
    {
        var selections = new[]
        {
            new[] { 1, 0 },
            new[] { 0, 1 },
            new[] { 1, 0 }
        };

        var (proof, coms) = SelectionProof.Prove(3, 2, selections,
            new Sha256FiatShamirEngine(), _group);

        var err = SelectionProof.Verify(3, 2, coms, proof,
            new Sha256FiatShamirEngine(), _group);
        Assert.Null(err);
    }

    [Fact]
    public void TestAllGroupsSelectSameElement()
    {
        var selections = new[]
        {
            new[] { 0, 0, 1 },
            new[] { 0, 0, 1 },
            new[] { 0, 0, 1 }
        };

        var (proof, coms) = SelectionProof.Prove(3, 3, selections,
            new Sha256FiatShamirEngine(), _group);

        var err = SelectionProof.Verify(3, 3, coms, proof,
            new Sha256FiatShamirEngine(), _group);
        Assert.Null(err);
    }

    [Fact]
    public void TestWrongCommitmentsFailVerification()
    {
        var selections = new[] { new[] { 1, 0, 0 } };

        var (proof, _) = SelectionProof.Prove(1, 3, selections,
            new Sha256FiatShamirEngine(), _group);

        var fakeComs = new[] { _group.RandomPoint() };

        var err = SelectionProof.Verify(1, 3, fakeComs, proof,
            new Sha256FiatShamirEngine(), _group);
        Assert.NotNull(err);
    }
}
