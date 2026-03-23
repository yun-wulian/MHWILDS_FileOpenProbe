using System.Diagnostics;
using System.Text;

namespace MHWILDS.ModPackager;

internal sealed class NativePackerInvoker
{
    private const string PackerFileName = "mhwilds_pak_packer.exe";

    public async Task<string> EncryptPakAsync(
        string gameExePath,
        string inputPakPath,
        string outputMhwsmodPath,
        ModPackageMetadata metadata,
        CancellationToken cancellationToken)
    {
        var packerPath = ResolvePackerPath();
        if (packerPath is null)
        {
            throw new FileNotFoundException("找不到 mhwilds_pak_packer.exe，请先构建 native packer。");
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = packerPath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        startInfo.ArgumentList.Add(gameExePath);
        startInfo.ArgumentList.Add(inputPakPath);
        startInfo.ArgumentList.Add(outputMhwsmodPath);

        if (!string.IsNullOrWhiteSpace(metadata.ModVersion))
        {
            startInfo.ArgumentList.Add("--mod-version");
            startInfo.ArgumentList.Add(metadata.ModVersion);
        }

        if (!string.IsNullOrWhiteSpace(metadata.UpdateUrl))
        {
            startInfo.ArgumentList.Add("--update-url");
            startInfo.ArgumentList.Add(metadata.UpdateUrl);
        }

        if (!string.IsNullOrWhiteSpace(metadata.Author))
        {
            startInfo.ArgumentList.Add("--author");
            startInfo.ArgumentList.Add(metadata.Author);
        }

        using var process = new Process { StartInfo = startInfo };
        var output = new StringBuilder();

        process.Start();
        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        output.Append(await stdoutTask);
        output.Append(await stderrTask);

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"native packer 执行失败，退出码 {process.ExitCode}。\r\n{output}");
        }

        return output.ToString().Trim();
    }

    private static string? ResolvePackerPath()
    {
        var envOverride = Environment.GetEnvironmentVariable("MHWILDS_PAK_PACKER_EXE");
        if (!string.IsNullOrWhiteSpace(envOverride) && File.Exists(envOverride))
        {
            return envOverride;
        }

        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            AppContext.BaseDirectory,
            Directory.GetCurrentDirectory(),
        };

        foreach (var root in roots)
        {
            foreach (var directory in EnumerateSelfAndAncestors(root))
            {
                var direct = Path.Combine(directory, PackerFileName);
                if (File.Exists(direct))
                {
                    return direct;
                }

                foreach (var relative in new[]
                {
                    Path.Combine("build", "Release", PackerFileName),
                    Path.Combine("build", "RelWithDebInfo", PackerFileName),
                    Path.Combine("build", "Debug", PackerFileName),
                })
                {
                    var candidate = Path.Combine(directory, relative);
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }
        }

        return null;
    }

    private static IEnumerable<string> EnumerateSelfAndAncestors(string startDirectory)
    {
        var current = new DirectoryInfo(Path.GetFullPath(startDirectory));
        while (current is not null)
        {
            yield return current.FullName;
            current = current.Parent;
        }
    }
}
