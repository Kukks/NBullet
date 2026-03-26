using NBullet;
using NBullet.Secp256k1;

namespace NBullet.Tests;

public class NumberUtilsTests
{
    private readonly IGroup _group = Secp256k1Group.Instance;

    [Fact]
    public void TestUInt64Hex()
    {
        ulong x = 0xab4f0540ab4f0540;
        var hex = NumberUtils.UInt64Hex(x, _group);

        // Expected: [0, 4, 5, 0, 15, 4, 11, 10, 0, 4, 5, 0, 15, 4, 11, 10]
        int[] expected = { 0, 4, 5, 0, 15, 4, 11, 10, 0, 4, 5, 0, 15, 4, 11, 10 };
        Assert.Equal(16, hex.Length);
        for (int i = 0; i < 16; i++)
            Assert.Equal(expected[i], (int)hex[i].ToBigInteger());
    }

    [Fact]
    public void TestHexMapping()
    {
        ulong x = 0xab4f0540ab4f0540;
        var hex = NumberUtils.UInt64Hex(x, _group);
        var mapping = NumberUtils.HexMapping(hex, _group);

        // Expected: [4, 0, 0, 0, 4, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 2]
        int[] expected = { 4, 0, 0, 0, 4, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 2 };
        Assert.Equal(16, mapping.Length);
        for (int i = 0; i < 16; i++)
            Assert.Equal(expected[i], (int)mapping[i].ToBigInteger());
    }
}
