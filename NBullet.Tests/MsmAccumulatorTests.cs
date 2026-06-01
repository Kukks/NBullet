using NBullet;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class MsmAccumulatorTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Fact]
    public void Empty_SumIsInfinity()
    {
        var acc = new MsmAccumulator();
        Assert.True(acc.Sum(_group).IsInfinity);
        Assert.Equal(0, acc.Count);
    }

    [Fact]
    public void SingleAdd_MatchesScalarMul()
    {
        var p = _group.RandomPoint();
        var s = _group.RandomScalar();

        var acc = new MsmAccumulator();
        acc.Add(s, p);

        Assert.True(acc.Sum(_group).Eq(p.ScalarMul(s)));
    }

    [Fact]
    public void TwoAdds_MatchHandSum()
    {
        var p1 = _group.RandomPoint();
        var p2 = _group.RandomPoint();
        var s1 = _group.RandomScalar();
        var s2 = _group.RandomScalar();

        var acc = new MsmAccumulator();
        acc.Add(s1, p1);
        acc.Add(s2, p2);

        var expected = p1.ScalarMul(s1).Add(p2.ScalarMul(s2));
        Assert.True(acc.Sum(_group).Eq(expected));
    }

    [Fact]
    public void AddWeighted_FoldsOuterWeight()
    {
        var p = _group.RandomPoint();
        var outer = _group.RandomScalar();
        var inner = _group.RandomScalar();

        var acc = new MsmAccumulator();
        acc.AddWeighted(outer, inner, p);

        Assert.True(acc.Sum(_group).Eq(p.ScalarMul(outer.Mul(inner))));
    }

    [Fact]
    public void AddMany_LengthMismatchThrows()
    {
        var acc = new MsmAccumulator();
        Assert.Throws<ArgumentException>(() =>
            acc.AddMany(new IScalar[] { _group.RandomScalar() }, Array.Empty<IPoint>()));
    }
}
