using System.Drawing;

namespace MHWILDS.ModPackager;

public partial class MainForm
{
    private System.ComponentModel.IContainer components = null!;

    private ContextMenuStrip inputSourceContextMenu = null!;
    private ToolStripMenuItem inputSourceMenuItemDirectory = null!;
    private ToolStripMenuItem inputSourceMenuItemPak = null!;
    private TableLayoutPanel rootLayoutPanel = null!;
    private Label titleLabel = null!;
    private Label subtitleLabel = null!;
    private GroupBox pathGroupBox = null!;
    private TableLayoutPanel pathLayoutPanel = null!;
    private Label gameExeLabel = null!;
    private TextBox gameExePathTextBox = null!;
    private Button browseGameExeButton = null!;
    private Label inputLabel = null!;
    private TextBox inputPathTextBox = null!;
    private Button browseInputButton = null!;
    private Label inputKindLabel = null!;
    private Label inputKindValueLabel = null!;
    private Label outputLabel = null!;
    private TextBox outputPathTextBox = null!;
    private Button browseOutputButton = null!;
    private GroupBox metadataGroupBox = null!;
    private TableLayoutPanel metadataLayoutPanel = null!;
    private Label modVersionLabel = null!;
    private TextBox modVersionTextBox = null!;
    private Label updateUrlLabel = null!;
    private TextBox updateUrlTextBox = null!;
    private Label authorLabel = null!;
    private TextBox authorTextBox = null!;
    private Panel bottomPanel = null!;
    private FlowLayoutPanel statusFlowLayoutPanel = null!;
    private Label statusLabel = null!;
    private Label statusValueLabel = null!;
    private Button buildButton = null!;
    private GroupBox logGroupBox = null!;
    private TextBox logTextBox = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            components?.Dispose();
        }

        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        components = new System.ComponentModel.Container();
        inputSourceContextMenu = new ContextMenuStrip(components);
        inputSourceMenuItemDirectory = new ToolStripMenuItem();
        inputSourceMenuItemPak = new ToolStripMenuItem();
        rootLayoutPanel = new TableLayoutPanel();
        titleLabel = new Label();
        subtitleLabel = new Label();
        pathGroupBox = new GroupBox();
        pathLayoutPanel = new TableLayoutPanel();
        gameExePathTextBox = new TextBox();
        browseGameExeButton = new Button();
        inputLabel = new Label();
        inputPathTextBox = new TextBox();
        browseInputButton = new Button();
        inputKindLabel = new Label();
        inputKindValueLabel = new Label();
        outputLabel = new Label();
        outputPathTextBox = new TextBox();
        browseOutputButton = new Button();
        gameExeLabel = new Label();
        metadataGroupBox = new GroupBox();
        metadataLayoutPanel = new TableLayoutPanel();
        modVersionLabel = new Label();
        modVersionTextBox = new TextBox();
        updateUrlLabel = new Label();
        updateUrlTextBox = new TextBox();
        authorLabel = new Label();
        authorTextBox = new TextBox();
        bottomPanel = new Panel();
        statusFlowLayoutPanel = new FlowLayoutPanel();
        statusLabel = new Label();
        statusValueLabel = new Label();
        buildButton = new Button();
        logGroupBox = new GroupBox();
        logTextBox = new TextBox();
        inputSourceContextMenu.SuspendLayout();
        rootLayoutPanel.SuspendLayout();
        pathGroupBox.SuspendLayout();
        pathLayoutPanel.SuspendLayout();
        metadataGroupBox.SuspendLayout();
        metadataLayoutPanel.SuspendLayout();
        bottomPanel.SuspendLayout();
        logGroupBox.SuspendLayout();
        SuspendLayout();
        // 
        // inputSourceContextMenu
        // 
        inputSourceContextMenu.ImageScalingSize = new Size(20, 20);
        inputSourceContextMenu.Items.AddRange(new ToolStripItem[] { inputSourceMenuItemDirectory, inputSourceMenuItemPak });
        inputSourceContextMenu.Name = "inputSourceContextMenu";
        inputSourceContextMenu.Size = new Size(152, 48);
        // 
        // inputSourceMenuItemDirectory
        // 
        inputSourceMenuItemDirectory.Name = "inputSourceMenuItemDirectory";
        inputSourceMenuItemDirectory.Size = new Size(151, 22);
        inputSourceMenuItemDirectory.Text = "选择散件目录";
        // 
        // inputSourceMenuItemPak
        // 
        inputSourceMenuItemPak.Name = "inputSourceMenuItemPak";
        inputSourceMenuItemPak.Size = new Size(151, 22);
        inputSourceMenuItemPak.Text = "选择现有 PAK";
        // 
        // rootLayoutPanel
        // 
        rootLayoutPanel.ColumnCount = 1;
        rootLayoutPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        rootLayoutPanel.Controls.Add(titleLabel, 0, 0);
        rootLayoutPanel.Controls.Add(subtitleLabel, 0, 1);
        rootLayoutPanel.Controls.Add(pathGroupBox, 0, 2);
        rootLayoutPanel.Controls.Add(metadataGroupBox, 0, 3);
        rootLayoutPanel.Controls.Add(bottomPanel, 0, 4);
        rootLayoutPanel.Controls.Add(logGroupBox, 0, 5);
        rootLayoutPanel.Dock = DockStyle.Fill;
        rootLayoutPanel.Location = new Point(10, 10);
        rootLayoutPanel.Name = "rootLayoutPanel";
        rootLayoutPanel.RowCount = 6;
        rootLayoutPanel.RowStyles.Add(new RowStyle());
        rootLayoutPanel.RowStyles.Add(new RowStyle());
        rootLayoutPanel.RowStyles.Add(new RowStyle());
        rootLayoutPanel.RowStyles.Add(new RowStyle());
        rootLayoutPanel.RowStyles.Add(new RowStyle());
        rootLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
        rootLayoutPanel.Size = new Size(765, 609);
        rootLayoutPanel.TabIndex = 0;
        // 
        // titleLabel
        // 
        titleLabel.AutoSize = true;
        titleLabel.Dock = DockStyle.Fill;
        titleLabel.Font = new Font("Microsoft YaHei UI", 15F, FontStyle.Bold, GraphicsUnit.Point, 134);
        titleLabel.Location = new Point(3, 0);
        titleLabel.Margin = new Padding(3, 0, 3, 5);
        titleLabel.Name = "titleLabel";
        titleLabel.Size = new Size(759, 27);
        titleLabel.TabIndex = 0;
        titleLabel.Text = "MHWILDS Mod Packager";
        // 
        // subtitleLabel
        // 
        subtitleLabel.AutoSize = true;
        subtitleLabel.Dock = DockStyle.Fill;
        subtitleLabel.ForeColor = SystemColors.GrayText;
        subtitleLabel.Location = new Point(3, 32);
        subtitleLabel.Margin = new Padding(3, 0, 3, 10);
        subtitleLabel.Name = "subtitleLabel";
        subtitleLabel.Size = new Size(759, 17);
        subtitleLabel.TabIndex = 1;
        subtitleLabel.Text = "支持散件目录或现有 PAK 输入，输出加密后的 .mhwsmod 文件。";
        subtitleLabel.Click += subtitleLabel_Click;
        // 
        // pathGroupBox
        // 
        pathGroupBox.Controls.Add(pathLayoutPanel);
        pathGroupBox.Dock = DockStyle.Top;
        pathGroupBox.Location = new Point(3, 62);
        pathGroupBox.Name = "pathGroupBox";
        pathGroupBox.Padding = new Padding(10, 8, 10, 10);
        pathGroupBox.Size = new Size(759, 180);
        pathGroupBox.TabIndex = 2;
        pathGroupBox.TabStop = false;
        pathGroupBox.Text = "路径与输出";
        pathGroupBox.Enter += pathGroupBox_Enter;
        // 
        // pathLayoutPanel
        // 
        pathLayoutPanel.ColumnCount = 3;
        pathLayoutPanel.ColumnStyles.Add(new ColumnStyle());
        pathLayoutPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        pathLayoutPanel.ColumnStyles.Add(new ColumnStyle());
        pathLayoutPanel.Controls.Add(gameExePathTextBox, 1, 0);
        pathLayoutPanel.Controls.Add(browseGameExeButton, 2, 0);
        pathLayoutPanel.Controls.Add(inputLabel, 0, 1);
        pathLayoutPanel.Controls.Add(inputPathTextBox, 1, 1);
        pathLayoutPanel.Controls.Add(browseInputButton, 2, 1);
        pathLayoutPanel.Controls.Add(inputKindLabel, 0, 2);
        pathLayoutPanel.Controls.Add(inputKindValueLabel, 1, 2);
        pathLayoutPanel.Controls.Add(outputLabel, 0, 3);
        pathLayoutPanel.Controls.Add(outputPathTextBox, 1, 3);
        pathLayoutPanel.Controls.Add(browseOutputButton, 2, 3);
        pathLayoutPanel.Controls.Add(gameExeLabel, 0, 0);
        pathLayoutPanel.Dock = DockStyle.Fill;
        pathLayoutPanel.Location = new Point(10, 24);
        pathLayoutPanel.Name = "pathLayoutPanel";
        pathLayoutPanel.RowCount = 4;
        pathLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 25F));
        pathLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 25F));
        pathLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 25F));
        pathLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 25F));
        pathLayoutPanel.Size = new Size(739, 146);
        pathLayoutPanel.TabIndex = 0;
        // 
        // gameExePathTextBox
        // 
        gameExePathTextBox.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        gameExePathTextBox.Location = new Point(67, 6);
        gameExePathTextBox.Name = "gameExePathTextBox";
        gameExePathTextBox.Size = new Size(567, 23);
        gameExePathTextBox.TabIndex = 1;
        // 
        // browseGameExeButton
        // 
        browseGameExeButton.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        browseGameExeButton.Location = new Point(640, 4);
        browseGameExeButton.Name = "browseGameExeButton";
        browseGameExeButton.Size = new Size(96, 27);
        browseGameExeButton.TabIndex = 2;
        browseGameExeButton.Text = "浏览...";
        browseGameExeButton.UseVisualStyleBackColor = true;
        // 
        // inputLabel
        // 
        inputLabel.Anchor = AnchorStyles.Left;
        inputLabel.AutoSize = true;
        inputLabel.Location = new Point(3, 45);
        inputLabel.Name = "inputLabel";
        inputLabel.Size = new Size(56, 17);
        inputLabel.TabIndex = 3;
        inputLabel.Text = "输入内容";
        // 
        // inputPathTextBox
        // 
        inputPathTextBox.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        inputPathTextBox.Location = new Point(67, 42);
        inputPathTextBox.Name = "inputPathTextBox";
        inputPathTextBox.Size = new Size(567, 23);
        inputPathTextBox.TabIndex = 4;
        // 
        // browseInputButton
        // 
        browseInputButton.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        browseInputButton.Location = new Point(640, 40);
        browseInputButton.Name = "browseInputButton";
        browseInputButton.Size = new Size(96, 27);
        browseInputButton.TabIndex = 5;
        browseInputButton.Text = "选择输入";
        browseInputButton.UseVisualStyleBackColor = true;
        // 
        // inputKindLabel
        // 
        inputKindLabel.Anchor = AnchorStyles.Left;
        inputKindLabel.AutoSize = true;
        inputKindLabel.Location = new Point(3, 81);
        inputKindLabel.Name = "inputKindLabel";
        inputKindLabel.Size = new Size(56, 17);
        inputKindLabel.TabIndex = 6;
        inputKindLabel.Text = "输入类型";
        // 
        // inputKindValueLabel
        // 
        inputKindValueLabel.Anchor = AnchorStyles.Left;
        inputKindValueLabel.AutoSize = true;
        inputKindValueLabel.BackColor = Color.FromArgb(242, 235, 229);
        inputKindValueLabel.ForeColor = Color.FromArgb(132, 88, 66);
        inputKindValueLabel.Location = new Point(67, 78);
        inputKindValueLabel.Margin = new Padding(3);
        inputKindValueLabel.Name = "inputKindValueLabel";
        inputKindValueLabel.Padding = new Padding(9, 3, 9, 3);
        inputKindValueLabel.Size = new Size(62, 23);
        inputKindValueLabel.TabIndex = 7;
        inputKindValueLabel.Text = "未识别";
        // 
        // outputLabel
        // 
        outputLabel.Anchor = AnchorStyles.Left;
        outputLabel.AutoSize = true;
        outputLabel.Location = new Point(3, 118);
        outputLabel.Name = "outputLabel";
        outputLabel.Size = new Size(56, 17);
        outputLabel.TabIndex = 8;
        outputLabel.Text = "输出路径";
        // 
        // outputPathTextBox
        // 
        outputPathTextBox.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        outputPathTextBox.Location = new Point(67, 115);
        outputPathTextBox.Name = "outputPathTextBox";
        outputPathTextBox.Size = new Size(567, 23);
        outputPathTextBox.TabIndex = 9;
        // 
        // browseOutputButton
        // 
        browseOutputButton.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        browseOutputButton.Location = new Point(640, 113);
        browseOutputButton.Name = "browseOutputButton";
        browseOutputButton.Size = new Size(96, 27);
        browseOutputButton.TabIndex = 10;
        browseOutputButton.Text = "保存到...";
        browseOutputButton.UseVisualStyleBackColor = true;
        // 
        // gameExeLabel
        // 
        gameExeLabel.Anchor = AnchorStyles.Left;
        gameExeLabel.AutoSize = true;
        gameExeLabel.Location = new Point(3, 9);
        gameExeLabel.Name = "gameExeLabel";
        gameExeLabel.Size = new Size(58, 17);
        gameExeLabel.TabIndex = 0;
        gameExeLabel.Text = "游戏 EXE";
        // 
        // metadataGroupBox
        // 
        metadataGroupBox.Controls.Add(metadataLayoutPanel);
        metadataGroupBox.Dock = DockStyle.Top;
        metadataGroupBox.Location = new Point(3, 248);
        metadataGroupBox.Name = "metadataGroupBox";
        metadataGroupBox.Padding = new Padding(10, 8, 10, 10);
        metadataGroupBox.Size = new Size(759, 161);
        metadataGroupBox.TabIndex = 3;
        metadataGroupBox.TabStop = false;
        metadataGroupBox.Text = "可选元数据";
        // 
        // metadataLayoutPanel
        // 
        metadataLayoutPanel.ColumnCount = 2;
        metadataLayoutPanel.ColumnStyles.Add(new ColumnStyle());
        metadataLayoutPanel.ColumnStyles.Add(new ColumnStyle());
        metadataLayoutPanel.Controls.Add(modVersionLabel, 0, 0);
        metadataLayoutPanel.Controls.Add(modVersionTextBox, 1, 0);
        metadataLayoutPanel.Controls.Add(updateUrlLabel, 0, 1);
        metadataLayoutPanel.Controls.Add(updateUrlTextBox, 1, 1);
        metadataLayoutPanel.Controls.Add(authorLabel, 0, 2);
        metadataLayoutPanel.Controls.Add(authorTextBox, 1, 2);
        metadataLayoutPanel.Dock = DockStyle.Fill;
        metadataLayoutPanel.Location = new Point(10, 24);
        metadataLayoutPanel.Name = "metadataLayoutPanel";
        metadataLayoutPanel.RowCount = 3;
        metadataLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 33.3333321F));
        metadataLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 33.3333321F));
        metadataLayoutPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 33.3333321F));
        metadataLayoutPanel.Size = new Size(739, 127);
        metadataLayoutPanel.TabIndex = 0;
        // 
        // modVersionLabel
        // 
        modVersionLabel.Anchor = AnchorStyles.Left;
        modVersionLabel.AutoSize = true;
        modVersionLabel.Location = new Point(3, 12);
        modVersionLabel.Name = "modVersionLabel";
        modVersionLabel.Size = new Size(67, 17);
        modVersionLabel.TabIndex = 0;
        modVersionLabel.Text = "MOD 版本";
        // 
        // modVersionTextBox
        // 
        modVersionTextBox.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        modVersionTextBox.Location = new Point(76, 9);
        modVersionTextBox.Name = "modVersionTextBox";
        modVersionTextBox.PlaceholderText = "例如 1.0.0";
        modVersionTextBox.Size = new Size(1007, 23);
        modVersionTextBox.TabIndex = 1;
        // 
        // updateUrlLabel
        // 
        updateUrlLabel.Anchor = AnchorStyles.Left;
        updateUrlLabel.AutoSize = true;
        updateUrlLabel.Location = new Point(3, 54);
        updateUrlLabel.Name = "updateUrlLabel";
        updateUrlLabel.Size = new Size(56, 17);
        updateUrlLabel.TabIndex = 2;
        updateUrlLabel.Text = "更新来源";
        // 
        // updateUrlTextBox
        // 
        updateUrlTextBox.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        updateUrlTextBox.Location = new Point(76, 51);
        updateUrlTextBox.Name = "updateUrlTextBox";
        updateUrlTextBox.PlaceholderText = "可选：填写帖子或发布页链接";
        updateUrlTextBox.Size = new Size(1007, 23);
        updateUrlTextBox.TabIndex = 3;
        // 
        // authorLabel
        // 
        authorLabel.Anchor = AnchorStyles.Left;
        authorLabel.AutoSize = true;
        authorLabel.Location = new Point(3, 97);
        authorLabel.Name = "authorLabel";
        authorLabel.Size = new Size(67, 17);
        authorLabel.TabIndex = 4;
        authorLabel.Text = "MOD 作者";
        // 
        // authorTextBox
        // 
        authorTextBox.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        authorTextBox.Location = new Point(76, 94);
        authorTextBox.Name = "authorTextBox";
        authorTextBox.PlaceholderText = "可选";
        authorTextBox.Size = new Size(1007, 23);
        authorTextBox.TabIndex = 5;
        // 
        // bottomPanel
        // 
        bottomPanel.Controls.Add(statusLabel);
        bottomPanel.Controls.Add(statusFlowLayoutPanel);
        bottomPanel.Controls.Add(statusValueLabel);
        bottomPanel.Controls.Add(buildButton);
        bottomPanel.Dock = DockStyle.Top;
        bottomPanel.Location = new Point(3, 415);
        bottomPanel.Name = "bottomPanel";
        bottomPanel.Size = new Size(759, 46);
        bottomPanel.TabIndex = 4;
        // 
        // statusFlowLayoutPanel
        // 
        statusFlowLayoutPanel.Anchor = AnchorStyles.Left;
        statusFlowLayoutPanel.AutoSize = true;
        statusFlowLayoutPanel.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        statusFlowLayoutPanel.Location = new Point(0, 13);
        statusFlowLayoutPanel.Margin = new Padding(0);
        statusFlowLayoutPanel.Name = "statusFlowLayoutPanel";
        statusFlowLayoutPanel.Size = new Size(0, 0);
        statusFlowLayoutPanel.TabIndex = 0;
        statusFlowLayoutPanel.WrapContents = false;
        // 
        // statusLabel
        // 
        statusLabel.Anchor = AnchorStyles.Left;
        statusLabel.AutoSize = true;
        statusLabel.Location = new Point(10, 13);
        statusLabel.Margin = new Padding(0);
        statusLabel.Name = "statusLabel";
        statusLabel.Size = new Size(35, 17);
        statusLabel.TabIndex = 0;
        statusLabel.Text = "状态:";
        // 
        // statusValueLabel
        // 
        statusValueLabel.Anchor = AnchorStyles.Left;
        statusValueLabel.AutoSize = true;
        statusValueLabel.Location = new Point(50, 13);
        statusValueLabel.Margin = new Padding(5, 0, 0, 0);
        statusValueLabel.Name = "statusValueLabel";
        statusValueLabel.Size = new Size(56, 17);
        statusValueLabel.TabIndex = 1;
        statusValueLabel.Text = "等待开始";
        // 
        // buildButton
        // 
        buildButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        buildButton.Font = new Font("Microsoft YaHei UI", 10.5F, FontStyle.Bold, GraphicsUnit.Point, 134);
        buildButton.Location = new Point(619, 7);
        buildButton.Name = "buildButton";
        buildButton.Size = new Size(127, 36);
        buildButton.TabIndex = 1;
        buildButton.Text = "开始打包";
        buildButton.UseVisualStyleBackColor = true;
        // 
        // logGroupBox
        // 
        logGroupBox.Controls.Add(logTextBox);
        logGroupBox.Dock = DockStyle.Fill;
        logGroupBox.Location = new Point(3, 467);
        logGroupBox.Name = "logGroupBox";
        logGroupBox.Padding = new Padding(10, 8, 10, 10);
        logGroupBox.Size = new Size(759, 139);
        logGroupBox.TabIndex = 5;
        logGroupBox.TabStop = false;
        logGroupBox.Text = "日志";
        // 
        // logTextBox
        // 
        logTextBox.Dock = DockStyle.Fill;
        logTextBox.Location = new Point(10, 24);
        logTextBox.Multiline = true;
        logTextBox.Name = "logTextBox";
        logTextBox.ReadOnly = true;
        logTextBox.ScrollBars = ScrollBars.Vertical;
        logTextBox.Size = new Size(739, 105);
        logTextBox.TabIndex = 0;
        // 
        // MainForm
        // 
        AutoScaleDimensions = new SizeF(7F, 17F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(785, 629);
        Controls.Add(rootLayoutPanel);
        MinimumSize = new Size(790, 618);
        Name = "MainForm";
        Padding = new Padding(10);
        StartPosition = FormStartPosition.CenterScreen;
        Text = "MHWILDS Mod Packager";
        inputSourceContextMenu.ResumeLayout(false);
        rootLayoutPanel.ResumeLayout(false);
        rootLayoutPanel.PerformLayout();
        pathGroupBox.ResumeLayout(false);
        pathLayoutPanel.ResumeLayout(false);
        pathLayoutPanel.PerformLayout();
        metadataGroupBox.ResumeLayout(false);
        metadataLayoutPanel.ResumeLayout(false);
        metadataLayoutPanel.PerformLayout();
        bottomPanel.ResumeLayout(false);
        bottomPanel.PerformLayout();
        logGroupBox.ResumeLayout(false);
        logGroupBox.PerformLayout();
        ResumeLayout(false);
    }
}
