using System.Text;

namespace MHWILDS.ModPackager;

internal sealed class PakBuilder
{
    private static ReadOnlySpan<byte> Magic => "KPKA"u8;
    private const byte MajorVersion = 4;
    private const byte MinorVersion = 0;
    private const ushort FeatureFlags = 0;
    private const uint HeaderHash = 0;
    private const int HeaderSize = 16;
    private const int EntrySize = 48;

    public PakBuildResult BuildPak(string inputDirectory, string outputPakPath)
    {
        if (string.IsNullOrWhiteSpace(inputDirectory))
        {
            throw new InvalidOperationException("散文件目录不能为空。");
        }

        if (!Directory.Exists(inputDirectory))
        {
            throw new DirectoryNotFoundException($"散文件目录不存在: {inputDirectory}");
        }

        var entries = CollectEntries(inputDirectory);
        if (entries.Count == 0)
        {
            throw new InvalidOperationException("散文件目录中没有找到可打包的文件。");
        }

        var outputDirectory = Path.GetDirectoryName(outputPakPath);
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }

        var headerRegionSize = HeaderSize + EntrySize * entries.Count;
        using var output = new FileStream(outputPakPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
        output.Position = headerRegionSize;

        long totalBytes = 0;
        foreach (var entry in entries)
        {
            entry.Offset = (ulong)output.Position;

            using var input = new FileStream(entry.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            input.CopyTo(output);

            var length = (ulong)input.Length;
            entry.CompressedSize = length;
            entry.UncompressedSize = length;
            totalBytes += input.Length;
        }

        output.Position = 0;
        using var writer = new BinaryWriter(output, Encoding.UTF8, leaveOpen: true);
        WriteHeader(writer, entries.Count);
        foreach (var entry in entries)
        {
            WriteEntry(writer, entry);
        }

        writer.Flush();

        return new PakBuildResult
        {
            OutputPakPath = outputPakPath,
            FileCount = entries.Count,
            TotalBytes = totalBytes,
        };
    }

    private static List<PakEntryModel> CollectEntries(string inputDirectory)
    {
        var results = new List<PakEntryModel>();
        foreach (var filePath in Directory.EnumerateFiles(inputDirectory, "*", SearchOption.AllDirectories))
        {
            var logicalPath = TryExtractLogicalPath(inputDirectory, filePath);
            if (logicalPath is null)
            {
                throw new InvalidOperationException(
                    $"文件路径中没有找到 'natives/' 起点，无法构建 RE Pak 路径: {filePath}");
            }

            results.Add(new PakEntryModel
            {
                SourcePath = filePath,
                LogicalPath = logicalPath,
                LowerHash = PathHash.ComputeLowerHash(logicalPath),
                UpperHash = PathHash.ComputeUpperHash(logicalPath),
            });
        }

        results.Sort(static (left, right) => string.Compare(left.LogicalPath, right.LogicalPath, StringComparison.OrdinalIgnoreCase));
        return results;
    }

    private static string? TryExtractLogicalPath(string inputDirectory, string filePath)
    {
        var relative = Path.GetRelativePath(inputDirectory, filePath).Replace('\\', '/');
        var index = relative.IndexOf("natives/", StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return null;
        }

        var logicalPath = relative[index..];
        while (logicalPath.Contains("//", StringComparison.Ordinal))
        {
            logicalPath = logicalPath.Replace("//", "/", StringComparison.Ordinal);
        }

        return logicalPath;
    }

    private static void WriteHeader(BinaryWriter writer, int entryCount)
    {
        writer.Write(Magic);
        writer.Write(MajorVersion);
        writer.Write(MinorVersion);
        writer.Write(FeatureFlags);
        writer.Write((uint)entryCount);
        writer.Write(HeaderHash);
    }

    private static void WriteEntry(BinaryWriter writer, PakEntryModel entry)
    {
        writer.Write(entry.LowerHash);
        writer.Write(entry.UpperHash);
        writer.Write(entry.Offset);
        writer.Write(entry.CompressedSize);
        writer.Write(entry.UncompressedSize);
        writer.Write((long)0);
        writer.Write((ulong)0);
    }

    private sealed class PakEntryModel
    {
        public required string SourcePath { get; init; }
        public required string LogicalPath { get; init; }
        public required uint LowerHash { get; init; }
        public required uint UpperHash { get; init; }
        public ulong Offset { get; set; }
        public ulong CompressedSize { get; set; }
        public ulong UncompressedSize { get; set; }
    }
}
