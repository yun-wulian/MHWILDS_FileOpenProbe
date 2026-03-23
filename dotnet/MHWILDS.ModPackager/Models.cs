namespace MHWILDS.ModPackager;

internal enum PackageInputKind
{
    Unknown = 0,
    Directory = 1,
    PakFile = 2,
}

internal sealed class ModPackageMetadata
{
    public string ModVersion { get; init; } = string.Empty;
    public string UpdateUrl { get; init; } = string.Empty;
    public string Author { get; init; } = string.Empty;

    public bool HasAnyValue =>
        !string.IsNullOrWhiteSpace(ModVersion) ||
        !string.IsNullOrWhiteSpace(UpdateUrl) ||
        !string.IsNullOrWhiteSpace(Author);
}

internal sealed class PackagerRequest
{
    public required string GameExePath { get; init; }
    public required string InputPath { get; init; }
    public required PackageInputKind InputKind { get; init; }
    public required string OutputMhwsmodPath { get; init; }
    public required ModPackageMetadata Metadata { get; init; }
}

internal sealed class PakBuildResult
{
    public required string OutputPakPath { get; init; }
    public required int FileCount { get; init; }
    public required long TotalBytes { get; init; }
}
