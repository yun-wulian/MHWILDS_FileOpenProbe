using System.ComponentModel;

namespace MHWILDS.ModPackager;

public partial class MainForm : Form
{
    private static readonly Color InputKindDirectoryBackColor = Color.FromArgb(234, 244, 230);
    private static readonly Color InputKindDirectoryForeColor = Color.FromArgb(52, 100, 61);
    private static readonly Color InputKindPakBackColor = Color.FromArgb(237, 241, 252);
    private static readonly Color InputKindPakForeColor = Color.FromArgb(56, 87, 149);
    private static readonly Color InputKindUnknownBackColor = Color.FromArgb(242, 235, 229);
    private static readonly Color InputKindUnknownForeColor = Color.FromArgb(132, 88, 66);

    private readonly PakBuilder _pakBuilder = new();
    private readonly NativePackerInvoker _nativePacker = new();

    private string _lastSuggestedOutputPath = string.Empty;
    private bool _suppressOutputUpdate;

    public MainForm()
    {
        InitializeComponent();

        inputSourceMenuItemDirectory.Click += OnBrowseInputDirectoryClicked;
        inputSourceMenuItemPak.Click += OnBrowseInputPakClicked;
        browseGameExeButton.Click += OnBrowseGameExeClicked;
        browseInputButton.Click += OnBrowseInputClicked;
        browseOutputButton.Click += OnBrowseOutputPathClicked;
        buildButton.Click += OnBuildClicked;
        inputPathTextBox.TextChanged += OnInputPathTextChanged;

        if (!IsDesignerHosted())
        {
            RefreshInputState();
            SuggestOutputPath(force: true);
        }
        else
        {
            ApplyBadgeStyle("未识别", InputKindUnknownBackColor, InputKindUnknownForeColor);
        }
    }

    private static bool IsDesignerHosted()
    {
        return LicenseManager.UsageMode == LicenseUsageMode.Designtime;
    }

    private void OnBrowseGameExeClicked(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "MonsterHunterWilds.exe|MonsterHunterWilds.exe|可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        gameExePathTextBox.Text = dialog.FileName;
        AppendLog($"已选择游戏 EXE: {dialog.FileName}");
    }

    private void OnBrowseInputClicked(object? sender, EventArgs e)
    {
        inputSourceContextMenu.Show(browseInputButton, new Point(0, browseInputButton.Height));
    }

    private void OnBrowseInputDirectoryClicked(object? sender, EventArgs e)
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = "选择包含 natives/... 的散件目录",
            UseDescriptionForTitle = true,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        inputPathTextBox.Text = dialog.SelectedPath;
        AppendLog($"已选择散件目录: {dialog.SelectedPath}");
    }

    private void OnBrowseInputPakClicked(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "RE Engine Pak (*.pak)|*.pak|所有文件 (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        inputPathTextBox.Text = dialog.FileName;
        AppendLog($"已选择现有 Pak: {dialog.FileName}");
    }

    private void OnBrowseOutputPathClicked(object? sender, EventArgs e)
    {
        Directory.CreateDirectory(DefaultOutputDirectory);

        using var dialog = new SaveFileDialog
        {
            Filter = "MHWILDS Mod Package (*.mhwsmod)|*.mhwsmod",
            AddExtension = true,
            DefaultExt = "mhwsmod",
            OverwritePrompt = true,
            InitialDirectory = DefaultOutputDirectory,
            FileName = string.IsNullOrWhiteSpace(outputPathTextBox.Text)
                ? Path.GetFileName(GetSuggestedOutputPath())
                : Path.GetFileName(outputPathTextBox.Text),
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        outputPathTextBox.Text = dialog.FileName;
        AppendLog($"已设置输出文件: {dialog.FileName}");
    }

    private void OnInputPathTextChanged(object? sender, EventArgs e)
    {
        RefreshInputState();
        SuggestOutputPath(force: false);
    }

    private async void OnBuildClicked(object? sender, EventArgs e)
    {
        try
        {
            var request = ValidateAndCreateRequest();
            SetBusyState(true, "正在处理输入...");

            string? pakPathToEncrypt = null;
            string? temporaryPakPath = null;

            try
            {
                if (request.InputKind == PackageInputKind.Directory)
                {
                    temporaryPakPath = Path.Combine(Path.GetTempPath(), $"mhwsmod_{Guid.NewGuid():N}.pak");
                    AppendLog("检测到散件目录输入，开始构建 plain pak。");

                    var pakResult = await Task.Run(() => _pakBuilder.BuildPak(request.InputPath, temporaryPakPath));
                    pakPathToEncrypt = pakResult.OutputPakPath;

                    AppendLog($"Pak 已生成: {pakResult.OutputPakPath}");
                    AppendLog($"文件数量: {pakResult.FileCount}，总字节数: {pakResult.TotalBytes}");
                }
                else
                {
                    pakPathToEncrypt = request.InputPath;
                    AppendLog("检测到现有 Pak 输入，跳过散件打包阶段。");
                }

                SetBusyState(true, "正在调用 native packer...");
                AppendLog("开始生成加密的 MHWSMOD 包。");

                var nativeOutput = await _nativePacker.EncryptPakAsync(
                    request.GameExePath,
                    pakPathToEncrypt!,
                    request.OutputMhwsmodPath,
                    request.Metadata,
                    CancellationToken.None);

                if (!string.IsNullOrWhiteSpace(nativeOutput))
                {
                    AppendLog(nativeOutput);
                }

                SetBusyState(false, "打包完成");
                AppendLog($"输出完成: {request.OutputMhwsmodPath}");

                MessageBox.Show(
                    this,
                    $"MHWSMOD 已生成：\r\n{request.OutputMhwsmodPath}",
                    "打包完成",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            finally
            {
                if (!string.IsNullOrWhiteSpace(temporaryPakPath))
                {
                    TryDeleteFile(temporaryPakPath);
                }
            }
        }
        catch (Exception ex)
        {
            SetBusyState(false, "打包失败");
            AppendLog(ex.ToString());
            MessageBox.Show(
                this,
                ex.Message,
                "打包失败",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }

    private PackagerRequest ValidateAndCreateRequest()
    {
        var gameExePath = gameExePathTextBox.Text.Trim();
        var inputPath = inputPathTextBox.Text.Trim();
        var outputPath = outputPathTextBox.Text.Trim();

        if (string.IsNullOrWhiteSpace(gameExePath) || !File.Exists(gameExePath))
        {
            throw new InvalidOperationException("请先选择有效的游戏 EXE 路径。");
        }

        var inputKind = DetectInputKind(inputPath);
        if (inputKind == PackageInputKind.Unknown)
        {
            throw new InvalidOperationException("请输入有效的散件目录或 .pak 文件。");
        }

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            outputPath = GetSuggestedOutputPath();
            outputPathTextBox.Text = outputPath;
        }

        if (!string.Equals(Path.GetExtension(outputPath), ".mhwsmod", StringComparison.OrdinalIgnoreCase))
        {
            outputPath += ".mhwsmod";
            outputPathTextBox.Text = outputPath;
        }

        var outputDirectory = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            Directory.CreateDirectory(outputDirectory);
        }

        return new PackagerRequest
        {
            GameExePath = gameExePath,
            InputPath = inputPath,
            InputKind = inputKind,
            OutputMhwsmodPath = outputPath,
            Metadata = new ModPackageMetadata
            {
                ModVersion = modVersionTextBox.Text.Trim(),
                UpdateUrl = updateUrlTextBox.Text.Trim(),
                Author = authorTextBox.Text.Trim(),
            },
        };
    }

    private void RefreshInputState()
    {
        var inputKind = DetectInputKind(inputPathTextBox.Text.Trim());
        switch (inputKind)
        {
            case PackageInputKind.Directory:
                ApplyBadgeStyle("散件目录", InputKindDirectoryBackColor, InputKindDirectoryForeColor);
                break;
            case PackageInputKind.PakFile:
                ApplyBadgeStyle("现有 PAK", InputKindPakBackColor, InputKindPakForeColor);
                break;
            default:
                ApplyBadgeStyle("未识别", InputKindUnknownBackColor, InputKindUnknownForeColor);
                break;
        }
    }

    private void ApplyBadgeStyle(string text, Color backColor, Color foreColor)
    {
        inputKindValueLabel.Text = text;
        inputKindValueLabel.BackColor = backColor;
        inputKindValueLabel.ForeColor = foreColor;
    }

    private void SuggestOutputPath(bool force)
    {
        if (!force && !CanReplaceOutputPath())
        {
            return;
        }

        var suggestedPath = GetSuggestedOutputPath();
        _suppressOutputUpdate = true;
        outputPathTextBox.Text = suggestedPath;
        _suppressOutputUpdate = false;
        _lastSuggestedOutputPath = suggestedPath;
    }

    private bool CanReplaceOutputPath()
    {
        if (_suppressOutputUpdate)
        {
            return false;
        }

        var current = outputPathTextBox.Text.Trim();
        return string.IsNullOrWhiteSpace(current) ||
               string.Equals(current, _lastSuggestedOutputPath, StringComparison.OrdinalIgnoreCase);
    }

    private string GetSuggestedOutputPath()
    {
        var baseName = "packaged_mod";
        var inputPath = inputPathTextBox.Text.Trim();
        var inputKind = DetectInputKind(inputPath);

        if (inputKind == PackageInputKind.Directory)
        {
            baseName = Path.GetFileName(inputPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        }
        else if (inputKind == PackageInputKind.PakFile)
        {
            baseName = Path.GetFileNameWithoutExtension(inputPath);
        }

        baseName = SanitizeFileName(string.IsNullOrWhiteSpace(baseName) ? "packaged_mod" : baseName);
        Directory.CreateDirectory(DefaultOutputDirectory);
        return Path.Combine(DefaultOutputDirectory, $"{baseName}.mhwsmod");
    }

    private static string DefaultOutputDirectory => Path.Combine(AppContext.BaseDirectory, "output");

    private static string SanitizeFileName(string name)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var chars = name.Select(ch => invalidChars.Contains(ch) ? '_' : ch).ToArray();
        return new string(chars);
    }

    private static PackageInputKind DetectInputKind(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return PackageInputKind.Unknown;
        }

        if (Directory.Exists(path))
        {
            return PackageInputKind.Directory;
        }

        if (File.Exists(path) && string.Equals(Path.GetExtension(path), ".pak", StringComparison.OrdinalIgnoreCase))
        {
            return PackageInputKind.PakFile;
        }

        return PackageInputKind.Unknown;
    }

    private void SetBusyState(bool busy, string statusText)
    {
        buildButton.Enabled = !busy;
        browseGameExeButton.Enabled = !busy;
        browseInputButton.Enabled = !busy;
        browseOutputButton.Enabled = !busy;
        statusValueLabel.Text = statusText;
        UseWaitCursor = busy;
        Cursor.Current = busy ? Cursors.WaitCursor : Cursors.Default;
    }

    private void AppendLog(string text)
    {
        if (logTextBox.TextLength > 0)
        {
            logTextBox.AppendText(Environment.NewLine);
        }

        logTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {text}");
        logTextBox.SelectionStart = logTextBox.TextLength;
        logTextBox.ScrollToCaret();
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
        }
    }

    private void pathGroupBox_Enter(object sender, EventArgs e)
    {

    }

    private void subtitleLabel_Click(object sender, EventArgs e)
    {

    }
}
