using System.Buffers.Binary;
using System.Numerics;

namespace MHWILDS.ModPackager;

internal static class PathHash
{
    private const uint MurmurSeed = 0xFFFFFFFF;

    public static ulong ComputeMixedHash(string logicalPath)
    {
        var lower = ComputeHash32(logicalPath, uppercase: false);
        var upper = ComputeHash32(logicalPath, uppercase: true);
        return ((ulong)upper << 32) | lower;
    }

    public static uint ComputeLowerHash(string logicalPath) => ComputeHash32(logicalPath, uppercase: false);

    public static uint ComputeUpperHash(string logicalPath) => ComputeHash32(logicalPath, uppercase: true);

    private static uint ComputeHash32(string logicalPath, bool uppercase)
    {
        var data = EncodeUtf16LeAsciiCase(loglogicalPath: logicalPath, uppercase);
        return Murmur3_32(data, MurmurSeed);
    }

    private static byte[] EncodeUtf16LeAsciiCase(string loglogicalPath, bool uppercase)
    {
        var buffer = new byte[loglogicalPath.Length * 2];
        var offset = 0;

        foreach (var original in loglogicalPath)
        {
            var value = original;
            if (value <= 0x7F)
            {
                if (uppercase)
                {
                    if (value is >= 'a' and <= 'z')
                    {
                        value = (char)(value - 32);
                    }
                }
                else if (value is >= 'A' and <= 'Z')
                {
                    value = (char)(value + 32);
                }
            }

            buffer[offset++] = (byte)(value & 0xFF);
            buffer[offset++] = (byte)(value >> 8);
        }

        return buffer;
    }

    private static uint Murmur3_32(ReadOnlySpan<byte> data, uint seed)
    {
        const uint c1 = 0xCC9E2D51;
        const uint c2 = 0x1B873593;

        var hash = seed;
        var blockCount = data.Length / 4;

        for (var i = 0; i < blockCount; i++)
        {
            var block = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(i * 4, 4));
            block *= c1;
            block = BitOperations.RotateLeft(block, 15);
            block *= c2;

            hash ^= block;
            hash = BitOperations.RotateLeft(hash, 13);
            hash = hash * 5 + 0xE6546B64;
        }

        uint tail = 0;
        var tailIndex = blockCount * 4;
        switch (data.Length & 3)
        {
            case 3:
                tail ^= (uint)data[tailIndex + 2] << 16;
                goto case 2;
            case 2:
                tail ^= (uint)data[tailIndex + 1] << 8;
                goto case 1;
            case 1:
                tail ^= data[tailIndex];
                tail *= c1;
                tail = BitOperations.RotateLeft(tail, 15);
                tail *= c2;
                hash ^= tail;
                break;
        }

        hash ^= (uint)data.Length;
        hash ^= hash >> 16;
        hash *= 0x85EBCA6B;
        hash ^= hash >> 13;
        hash *= 0xC2B2AE35;
        hash ^= hash >> 16;
        return hash;
    }
}
