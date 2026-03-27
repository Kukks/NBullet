using NBullet;
using NBullet.BouncyCastle;
using NBullet.Secp256k1;
using static NBullet.VectorMath;

namespace NBullet.Tests;

public class ArithmeticCircuitTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Theory]
    [InlineData(true)]  // Keccak
    [InlineData(false)] // SHA-256
    public void TestArithmeticCircuit(bool useKeccak)
    {
        // Test the knowledge of x, y for public z, r, such:
        // x + y = r
        // x * y = z

        var x = S(3);
        var y = S(5);
        var r = S(8);
        var z = S(15);

        var wl = new IScalar[] { x };
        var wr = new IScalar[] { y };
        var wo = new IScalar[] { z, r };
        var wv = new IScalar[] { x, y };

        int Nm = 1, No = 2, Nv = 2, K = 1;
        int Nl = Nv * K;
        int Nw = Nm + Nm + No;

        var Wm = new IScalar[][]
        {
            new[] { S(0), S(0), S(1), S(0) }
        };
        var Am = new IScalar[] { S(0) };

        var Wl = new IScalar[][]
        {
            new[] { S(0), S(1), S(0), S(0) },
            new[] { S(0), S(-1), S(1), S(0) }
        };
        var Al = new IScalar[] { r.Negate(), z.Negate() };

        // Circuit check: Wm * w should equal wl o wr (Hadamard product)
        var w = wl.Concat(wr).Concat(wo).ToArray();
        var wmResult = VectorMul(Wm[0], w, _group);
        var hadamard = VectorMul(wl, wr, _group);
        Assert.Equal(wmResult.ToBigInteger(), hadamard.ToBigInteger());

        var wnla = Wnla.NewWeightNormLinearPublic(16, 1, _group);

        var pub = new ArithmeticCircuitPublic
        {
            Nm = Nm, Nl = Nl, Nv = Nv, Nw = Nw, No = No, K = K,
            G = wnla.G, GVec = wnla.GVec[..Nm], HVec = wnla.HVec[..(9 + Nv)],
            Wm = Wm, Wl = Wl, Am = Am, Al = Al,
            Fl = true, Fm = false,
            F = (typ, index) => typ == PartitionType.LL ? index : null,
            GVec_ = wnla.GVec[Nm..], HVec_ = wnla.HVec[(9 + Nv)..]
        };

        var priv = new ArithmeticCircuitPrivate
        {
            V = new[] { wv },
            Sv = new[] { _group.RandomScalar() },
            Wl = wl, Wr = wr, Wo = wo
        };

        var V = new IPoint[pub.K];
        for (int i = 0; i < pub.K; i++)
            V[i] = ArithmeticCircuit.CommitCircuit(pub, priv.V[i], priv.Sv[i], _group);

        IFiatShamirEngine MakeFs() => useKeccak ? new KeccakFiatShamirEngine() : new Sha256FiatShamirEngine();

        var proof = ArithmeticCircuit.ProveCircuit(pub, V, MakeFs(), priv, _group);
        var err = ArithmeticCircuit.VerifyCircuit(pub, V, MakeFs(), proof, _group);

        Assert.Null(err);
    }

    [Theory]
    [InlineData(true)]  // Keccak
    [InlineData(false)] // SHA-256
    public void TestArithmeticCircuitBinaryRangeProof(bool useKeccak)
    {
        // value = bin(0110) = dec(6)
        // Prove every value[i] * (value[i] - 1) = 0 (each digit is a bit)
        var value = new IScalar[] { S(0), S(1), S(1), S(0) };

        int Nm = 4, No = 4, Nv = 2, K = 4;
        int Nl = Nv * K;
        int Nw = Nm + Nm + No;

        var a = HadamardMul(value, value);

        var v = new IScalar[][]
        {
            new[] { value[0], a[0] },
            new[] { value[1], a[1] },
            new[] { value[2], a[2] },
            new[] { value[3], a[3] }
        };

        var wl = value;
        var wr = value;
        var wo = a;

        // Verify constraint: Wm * w = wl o wr
        var w = wl.Concat(wr).Concat(wo).ToArray();
        var wv = v.SelectMany(vi => vi).ToArray();

        var Wm = new IScalar[Nm][];
        for (int i = 0; i < Nm; i++)
        {
            Wm[i] = new IScalar[Nw];
            for (int j = 0; j < Nw; j++)
                Wm[i][j] = S(0);
            Wm[i][8 + i] = S(1); // wo position
        }

        // Circuit check
        var wmResults = new IScalar[Nm];
        for (int i = 0; i < Nm; i++)
            wmResults[i] = VectorMul(Wm[i], w, _group);
        var hadamardResult = HadamardMul(wl, wr);
        for (int i = 0; i < Nm; i++)
            Assert.Equal(wmResults[i].ToBigInteger(), hadamardResult[i].ToBigInteger());

        var Am = ZeroVector(_group, Nm);

        var Wl = new IScalar[Nl][];
        for (int i = 0; i < Nl; i++)
        {
            Wl[i] = new IScalar[Nw];
            for (int j = 0; j < Nw; j++)
                Wl[i][j] = S(0);
        }

        // Each pair of Wl rows constrains one bit:
        for (int i = 0; i < 4; i++)
        {
            Wl[2 * i][i] = S(-1);
            Wl[2 * i + 1][i] = S(-1);
        }

        var Al = ZeroVector(_group, Nl);

        // Linear constraint check: Wl * w + wv + Al = 0
        var wlResults = new IScalar[Nl];
        for (int i = 0; i < Nl; i++)
            wlResults[i] = VectorMul(Wl[i], w, _group);
        var linCheck = VectorAdd(VectorAdd(wlResults, wv, _group), Al, _group);
        for (int i = 0; i < Nl; i++)
            Assert.True(linCheck[i].IsZero, $"Linear constraint {i} not satisfied");

        var wnla = Wnla.NewWeightNormLinearPublic(16, Nm, _group);

        var pub = new ArithmeticCircuitPublic
        {
            Nm = Nm, Nl = Nl, Nv = Nv, Nw = Nw, No = No, K = K,
            G = wnla.G, GVec = wnla.GVec[..Nm], HVec = wnla.HVec[..(9 + Nv)],
            Wm = Wm, Wl = Wl, Am = Am, Al = Al,
            Fl = true, Fm = false,
            F = (typ, index) => typ == PartitionType.NO ? index : null,
            GVec_ = wnla.GVec[Nm..], HVec_ = wnla.HVec[(9 + Nv)..]
        };

        var priv = new ArithmeticCircuitPrivate
        {
            V = v,
            Sv = new[] { _group.RandomScalar(), _group.RandomScalar(), _group.RandomScalar(), _group.RandomScalar() },
            Wl = wl, Wr = wr, Wo = wo
        };

        var V = new IPoint[pub.K];
        for (int i = 0; i < pub.K; i++)
            V[i] = ArithmeticCircuit.CommitCircuit(pub, priv.V[i], priv.Sv[i], _group);

        IFiatShamirEngine MakeFs() => useKeccak ? new KeccakFiatShamirEngine() : new Sha256FiatShamirEngine();

        var proof = ArithmeticCircuit.ProveCircuit(pub, V, MakeFs(), priv, _group);
        var err = ArithmeticCircuit.VerifyCircuit(pub, V, MakeFs(), proof, _group);

        Assert.Null(err);
    }

    [Fact]
    public void TestArithmeticCircuit_WrongWitness_Fails()
    {
        // Same circuit as TestArithmeticCircuit but with wrong witness
        var x = S(3);
        var y = S(5);
        var r = S(8);
        var z = S(15);

        // WRONG: using y=6 instead of y=5 (doesn't satisfy x*y=z)
        var wrongY = S(6);

        var wl = new IScalar[] { x };
        var wr = new IScalar[] { wrongY };
        var wo = new IScalar[] { z, r };
        var wv = new IScalar[] { x, wrongY };

        int Nm = 1, No = 2, Nv = 2, K = 1;
        int Nl = Nv * K;
        int Nw = Nm + Nm + No;

        var Wm = new IScalar[][]
        {
            new[] { S(0), S(0), S(1), S(0) }
        };
        var Am = new IScalar[] { S(0) };

        var Wl = new IScalar[][]
        {
            new[] { S(0), S(1), S(0), S(0) },
            new[] { S(0), S(-1), S(1), S(0) }
        };
        var Al = new IScalar[] { r.Negate(), z.Negate() };

        var wnla = Wnla.NewWeightNormLinearPublic(16, 1, _group);

        var pub = new ArithmeticCircuitPublic
        {
            Nm = Nm, Nl = Nl, Nv = Nv, Nw = Nw, No = No, K = K,
            G = wnla.G, GVec = wnla.GVec[..Nm], HVec = wnla.HVec[..(9 + Nv)],
            Wm = Wm, Wl = Wl, Am = Am, Al = Al,
            Fl = true, Fm = false,
            F = (typ, index) => typ == PartitionType.LL ? index : null,
            GVec_ = wnla.GVec[Nm..], HVec_ = wnla.HVec[(9 + Nv)..]
        };

        var priv = new ArithmeticCircuitPrivate
        {
            V = new[] { wv },
            Sv = new[] { _group.RandomScalar() },
            Wl = wl, Wr = wr, Wo = wo
        };

        var V = new IPoint[pub.K];
        for (int i = 0; i < pub.K; i++)
            V[i] = ArithmeticCircuit.CommitCircuit(pub, priv.V[i], priv.Sv[i], _group);

        var proof = ArithmeticCircuit.ProveCircuit(pub, V, new KeccakFiatShamirEngine(), priv, _group);
        var err = ArithmeticCircuit.VerifyCircuit(pub, V, new KeccakFiatShamirEngine(), proof, _group);

        Assert.NotNull(err);
    }

    private IScalar S(int v) => _group.ScalarFromInt(v);
}
