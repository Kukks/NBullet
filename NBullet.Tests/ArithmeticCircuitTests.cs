using NBullet;
using NBullet.BouncyCastle;
using NBullet.Secp256k1;
using static NBullet.VectorMath;

namespace NBullet.Tests;

public class ArithmeticCircuitTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Fact]
    public void TestArithmeticCircuit()
    {
        // Test the knowledge of x, y for public z, r, such:
        // x + y = r
        // x * y = z

        var x = _group.ScalarFromInt(3);
        var y = _group.ScalarFromInt(5);
        var r = _group.ScalarFromInt(8);
        var z = _group.ScalarFromInt(15);

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

        Assert.Null(err);
    }

    [Fact]
    public void TestArithmeticCircuitBinaryRangeProof()
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

        var Wm = new IScalar[Nm][];
        for (int i = 0; i < Nm; i++)
        {
            Wm[i] = new IScalar[Nw];
            for (int j = 0; j < Nw; j++)
                Wm[i][j] = S(0);
            Wm[i][8 + i] = S(1); // wo position
        }

        var Am = ZeroVector(_group, Nm);

        var Wl = new IScalar[Nl][];
        for (int i = 0; i < Nl; i++)
        {
            Wl[i] = new IScalar[Nw];
            for (int j = 0; j < Nw; j++)
                Wl[i][j] = S(0);
        }

        // Each pair of Wl rows constrains one bit:
        // Wl[2*i][i] = -1 (maps wl[i] = value[i])
        // Wl[2*i+1][i] = -1 (maps wr[i] = value[i])
        for (int i = 0; i < 4; i++)
        {
            Wl[2 * i][i] = S(-1);
            Wl[2 * i + 1][i] = S(-1);
        }

        var Al = ZeroVector(_group, Nl);

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

        var proof = ArithmeticCircuit.ProveCircuit(pub, V, new KeccakFiatShamirEngine(), priv, _group);
        var err = ArithmeticCircuit.VerifyCircuit(pub, V, new KeccakFiatShamirEngine(), proof, _group);

        Assert.Null(err);
    }

    private IScalar S(int v) => _group.ScalarFromInt(v);
}
