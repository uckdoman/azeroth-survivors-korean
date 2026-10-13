using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyTitle("Azeroth Survivors 한국어 패치")]
[assembly: AssemblyDescription("게임 폴더에 넣고 실행하는 한국어 패치 설치기")]
[assembly: AssemblyVersion("0.71.4.9")]

internal static class Installer
{
    const string OverlayHash = "aba0e46a60c39064d477fe9df7ee8c5d84b06bbd8b648c126ae2dc2c362d788a";
    const string Title = "아제로스 서바이버 한글 패치";
    const string PatchVersion = "0.71.4.9";
    const string RetryMessage = "설치하지 못했습니다. 게임을 종료하고 다시 실행해 주세요.";
    static readonly string[] PreviousOverlayHashes = {
        "60268bcad6a3817a621a47e6f745e3a353fadf0ad85ec7f0a92b09dda1eb452f",
        "831eb84a21736635210f2016ec0329e263c9dab781e92bd467896072c5c87260",
        "3ab8c0163c5b1c00ef0e56edc9d7ebb12afe3bdc67d39a7cb1ac8e80a74c79df"
    };
    // 이전 설치기가 적용한 동일 빌드만 원본 백업으로 되돌립니다.
    static readonly string[,] LegacySources = {
        { "1de76826e449fa8c3a745f5c53b1af47bab8c29c66155c67cb27b5ff4d1bbc75", "f497c0589920e2fdd8c84d89b6602592bd7c609dccd55b39ea27578cc10f495a" },
        { "1c5f5732b6c59264421153cec08238deba005ea2e58d953fe1d63b8b30c38179", "f497c0589920e2fdd8c84d89b6602592bd7c609dccd55b39ea27578cc10f495a" },
        { "6cc6aeb6c9b1f58f23997eb5b9f5c3f791c3ae310b359b0e9b67d8b05bd54d68", "180dd51036e9c0c6b60a27e39869e80b8397a6d2ea0a73fc8c57ee3dd7b7f22f" },
        { "41b4bdcaede8a3603e973a340dbcf17656ea315f0337d3749ea05985353ea23e", "7ba19a01591f95b48c1bf377199c6bb258d7ee61b97ef1992857a4b051321e28" },
        { "c902b1aa057f89bd4ef238cfb73adec8d345acf4780940cb96f78bdb29eb15a8", "41161a556ed31e6c4fef3d1621d308c625daa6a8d55e8f2f8464db494fbc9e21" }
    };
    sealed class UserError : Exception { internal UserError(string message) : base(message) { } }
    sealed class InstalledState
    {
        internal string Version, SourceHash, PatchedHash, TranslationHash, OverlayHash, SourceBackup;
        internal bool Restored;
    }

    [STAThread]
    static int Main(string[] args)
    {
        bool quiet = Array.IndexOf(args, "/quiet") >= 0;
        bool restore = Array.IndexOf(args, "/restore") >= 0;
        bool skipUpdate = Array.IndexOf(args, "/skip-update") >= 0;
        try
        {
            string folder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string game = Path.Combine(folder, "AzerothSurvivors.exe");
            string overlay = Path.Combine(folder, "Data", "patch-Z.MPQ");
            string backupDir = Path.Combine(folder, ".azeroth-ko");
            string legacyBackupDir = Path.Combine(folder, "한글패치_원본백업");
            if (!File.Exists(game)) throw new UserError("설치기를 게임 폴더에 넣고 다시 실행해 주세요.");
            PatchProgress.Open(!quiet, restore ? "영문판으로 복원하고 있습니다." :
                skipUpdate ? "설치를 준비하고 있습니다." : "최신 한글 패치를 확인하고 있습니다.");
            // 새 설치기가 직접 설치 잠금을 얻도록 먼저 위임합니다.
            if (!restore && !skipUpdate && InstallerUpdate.TryInstallLatest(folder, new Version(PatchVersion), quiet))
            {
                Tell(InstallMessage(false), quiet);
                return 0;
            }
            using (var installLock = new FileStream(Path.Combine(folder, ".azeroth-ko-install.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose))
            {
                CheckGameStopped();
                string current = Hash(game);
                NativeMachine(game);
                InstalledState oldState = ReadState(backupDir) ?? ReadState(legacyBackupDir);
                bool hasOverlay = File.Exists(overlay);
                string currentOverlayHash = hasOverlay ? Hash(overlay) : null;
                if (hasOverlay && !OwnedOverlay(currentOverlayHash, oldState))
                    throw new UserError("다른 한글 패치가 적용되어 있습니다. 원본 게임에 다시 설치해 주세요.");
                if (!restore)
                {
                    bool restoredState;
                    Version installedVersion;
                    try { installedVersion = Launcher.ReadInstalledVersion(folder, out restoredState); }
                    catch { installedVersion = new Version(0, 0, 0, 0); restoredState = false; }
                    if (!restoredState && installedVersion > new Version(PatchVersion))
                    {
                        if (oldState == null || current != oldState.PatchedHash || currentOverlayHash != oldState.OverlayHash ||
                            !File.Exists(Path.Combine(folder, "AzerothSurvivors_KoreanLauncher.exe")))
                            throw new UserError("최신 한글 패치로 다시 설치해 주세요.");
                        Tell(InstallMessage(false), quiet);
                        return 0;
                    }
                }

                EnsureStorage(backupDir);
                string nativeSource = game;
                string sourceHash = current;
                if (oldState != null && !oldState.Restored && current == oldState.PatchedHash)
                {
                    sourceHash = oldState.SourceHash;
                    nativeSource = SourceBackup(backupDir, sourceHash, oldState.SourceBackup);
                }
                else
                {
                    for (int i = 0; i < LegacySources.GetLength(0); i++)
                    {
                        if (current != LegacySources[i, 0]) continue;
                        sourceHash = LegacySources[i, 1];
                        nativeSource = LegacyBackup(backupDir, sourceHash);
                        break;
                    }
                }
                string sourceRelative = BackupRelative(sourceHash);
                string sourceDir = Path.Combine(backupDir, "source-" + sourceHash.Substring(0, 16));
                string backup = Path.Combine(sourceDir, "AzerothSurvivors.exe");
                PatchProgress.Report("원본 게임을 준비하고 있습니다.");
                string stage = Path.Combine(folder, ".azeroth-ko-stage-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(stage);
                string runtime = Path.Combine(backupDir, "translation-runtime");
                string runtimeNext = Path.Combine(stage, "runtime-next");
                string runtimeBefore = Path.Combine(stage, "runtime-before");
                bool oldRuntimeMoved = false, newRuntimeMoved = false, committed = false, preserveStage = false;
                try
                {
                    string previousGame = Path.Combine(stage, "current.exe");
                    string before = Path.Combine(stage, "before.exe");
                    string next = Path.Combine(stage, "next.exe");
                    string nextOverlay = Path.Combine(stage, "patch-Z.MPQ");
                    string overlayBefore = Path.Combine(stage, "overlay-before.MPQ");
                    string oldOverlay = Path.Combine(stage, "previous.MPQ");
                    File.Copy(game, previousGame);
                    if (Hash(previousGame) != current) throw new IOException("Game changed while staging.");
                    File.Copy(nativeSource, before);
                    if (Hash(before) != sourceHash) throw new IOException("Original game backup changed while staging.");
                    NativeMachine(before);
                    if (hasOverlay) File.Copy(overlay, overlayBefore);
                    string translationsHash = oldState == null ? null : oldState.TranslationHash;
                    if (restore)
                    {
                        if (translationsHash == null) translationsHash = TranslationDigest(runtime);
                        File.Copy(before, next);
                    }
                    else
                    {
                        ExtractRuntime(runtimeNext);
                        translationsHash = Hash(Path.Combine(runtimeNext, "translations.json"));
                        Directory.CreateDirectory(backupDir);
                        if (Directory.Exists(runtime)) { Directory.Move(runtime, runtimeBefore); oldRuntimeMoved = true; }
                        Directory.Move(runtimeNext, runtime);
                        newRuntimeMoved = true;
                        Translate(runtime, before, next, stage, Path.Combine(folder, "Data"), nextOverlay);
                        if (NativeMachine(next) != NativeMachine(before) ||
                            FileVersionInfo.GetVersionInfo(next).FileVersion != FileVersionInfo.GetVersionInfo(before).FileVersion)
                            throw new InvalidDataException("Translator changed the native game identity.");
                    }
                    string patchedHash = Hash(next);
                    string stagedOverlayHash = restore ? currentOverlayHash : Hash(nextOverlay);
                    EnsureBackup(before, backup, sourceHash);
                    if (!restore)
                    {
                        using (Stream payload = Assembly.GetExecutingAssembly().GetManifestResourceStream("patch.zip"))
                        using (var zip = new ZipArchive(payload, ZipArchiveMode.Read))
                        {
                            if (zip.GetEntry("FONT-LICENSE.txt") != null) Extract(zip.GetEntry("FONT-LICENSE.txt"), Path.Combine(sourceDir, "FONT-LICENSE.txt"));
                            if (zip.GetEntry("README.txt") != null) Extract(zip.GetEntry("README.txt"), Path.Combine(sourceDir, "README.txt"));
                        }
                    }
                    var state = new InstalledState { Version = PatchVersion, SourceHash = sourceHash, PatchedHash = patchedHash,
                        TranslationHash = translationsHash, OverlayHash = stagedOverlayHash ?? OverlayHash,
                        SourceBackup = sourceRelative, Restored = restore };
                    PatchProgress.Report(restore ? "영문판으로 복원하고 있습니다." : "번역을 적용하고 있습니다.");
                    CheckGameStopped();
                    if (Hash(game) != current || File.Exists(overlay) != hasOverlay || (hasOverlay && Hash(overlay) != currentOverlayHash))
                        throw new IOException("Game files changed while installing.");
                    bool gameChanged = false, overlayMoved = false, pendingLauncher = false;
                    try
                    {
                        // 공식 업데이트로 바뀐 게임은 과거 백업으로 덮어쓰지 않습니다.
                        if (patchedHash != current) { File.Replace(next, game, null); gameChanged = true; }
                        if (restore && hasOverlay) { File.Move(overlay, oldOverlay); overlayMoved = true; }
                        else if (!restore && !hasOverlay)
                        {
                            Directory.CreateDirectory(Path.GetDirectoryName(overlay));
                            File.Move(nextOverlay, overlay); overlayMoved = true;
                        }
                        else if (!restore && currentOverlayHash != stagedOverlayHash)
                        {
                            File.Replace(nextOverlay, overlay, null); overlayMoved = true;
                        }
                        if (Hash(game) != patchedHash || (!restore && Hash(overlay) != stagedOverlayHash))
                            throw new IOException("Applied files did not match staged files.");
                        if (restore) WriteState(backupDir, state, true);
                        else pendingLauncher = InstallLauncher(folder, backupDir, state);
                        committed = true;
                    }
                    catch (Exception failure)
                    {
                        Exception recoveryError = null;
                        try
                        {
                            if (overlayMoved)
                            {
                                if (restore) File.Move(oldOverlay, overlay);
                                else if (hasOverlay) File.Replace(overlayBefore, overlay, null);
                                else File.Delete(overlay);
                            }
                        }
                        catch (Exception recovery) { recoveryError = recovery; }
                        try { if (gameChanged) File.Replace(previousGame, game, null); }
                        catch (Exception recovery) { recoveryError = recovery; }
                        if (recoveryError != null)
                        {
                            preserveStage = true;
                            throw new IOException("Rollback failed; stage=" + stage, new AggregateException(failure, recoveryError));
                        }
                        throw;
                    }
                    Tell(restore ? "영문판으로 복원했습니다." : InstallMessage(pendingLauncher), quiet);
                }
                finally
                {
                    if (!committed)
                    {
                        try
                        {
                            if (newRuntimeMoved) Directory.Move(runtime, runtimeNext);
                            if (oldRuntimeMoved) Directory.Move(runtimeBefore, runtime);
                        }
                        catch (Exception recovery)
                        {
                            preserveStage = true;
                            throw new IOException("Translator runtime rollback failed; stage=" + stage, recovery);
                        }
                    }
                    if (!preserveStage) DeleteStage(stage, folder);
                }
            }
            return 0;
        }
        catch (Exception error)
        {
            PatchProgress.Close();
            string message = error is UserError || error is InstallerUpdate.UpdateError ? error.Message : RetryMessage;
            if (quiet) Console.Error.WriteLine(message);
            else MessageBox.Show(message, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        finally { PatchProgress.Close(); }
    }

    static bool OwnedOverlay(string hash, InstalledState state)
    {
        return hash == OverlayHash || Array.IndexOf(PreviousOverlayHashes, hash) >= 0 ||
            (state != null && hash == state.OverlayHash);
    }

    static string BackupRelative(string hash) { return "source-" + hash.Substring(0, 16) + "/AzerothSurvivors.exe"; }

    static string SourceBackup(string folder, string hash, string relative)
    {
        if (!String.Equals(relative.Replace('\\', '/'), BackupRelative(hash), StringComparison.OrdinalIgnoreCase))
            throw new UserError("원본 게임에 한글 패치를 다시 설치해 주세요.");
        return LegacyBackup(folder, hash);
    }

    static string LegacyBackup(string folder, string hash)
    {
        string previous = Path.Combine(Path.GetDirectoryName(folder), "한글패치_원본백업");
        foreach (string storage in new[] { folder, previous })
        {
            string path = Path.Combine(storage, "source-" + hash.Substring(0, 16), "AzerothSurvivors.exe");
            if (File.Exists(path) && Hash(path) == hash) return path;
            path = Path.Combine(storage, "AzerothSurvivors.exe");
            if (File.Exists(path) && Hash(path) == hash) return path;
        }
        throw new UserError("원본 게임에 한글 패치를 다시 설치해 주세요.");
    }

    static void EnsureStorage(string folder)
    {
        Directory.CreateDirectory(folder);
        File.SetAttributes(folder, File.GetAttributes(folder) | FileAttributes.Hidden);
    }

    static void EnsureBackup(string source, string backup, string hash)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(backup));
        if (File.Exists(backup))
        {
            if (Hash(backup) != hash) throw new UserError("원본 게임에 한글 패치를 다시 설치해 주세요.");
            return;
        }
        string temporary = backup + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.Copy(source, temporary);
            if (Hash(temporary) != hash) throw new IOException("Original backup integrity.");
            File.Move(temporary, backup);
        }
        finally { DeleteTemporary(temporary); }
    }

    static void ExtractRuntime(string destination)
    {
        Directory.CreateDirectory(destination);
        string root = Path.GetFullPath(destination) + Path.DirectorySeparatorChar;
        using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("translation-runtime.zip"))
        using (var zip = new ZipArchive(resource, ZipArchiveMode.Read))
        {
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                string relative = entry.FullName.Replace('/', Path.DirectorySeparatorChar);
                string path = Path.GetFullPath(Path.Combine(destination, relative));
                if (Path.IsPathRooted(relative) || !path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Translator resource path.");
                if (entry.FullName.EndsWith("/")) { Directory.CreateDirectory(path); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                using (Stream input = entry.Open())
                using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) input.CopyTo(output);
            }
        }
        if (!File.Exists(Path.Combine(destination, "translator.exe")) || !File.Exists(Path.Combine(destination, "translations.json")) ||
            !File.Exists(Path.Combine(destination, "overlay-template.mpq")) || !File.Exists(Path.Combine(destination, "asset_translations.json")))
            throw new InvalidDataException("Translator resource incomplete.");
    }

    static void Translate(string runtime, string input, string output, string stage, string dataFolder, string overlay)
    {
        var errors = new StringBuilder();
        var start = new ProcessStartInfo(Path.Combine(runtime, "translator.exe"),
            Quote(input) + " " + Quote(output) + " " + Quote(Path.Combine(runtime, "translations.json")) +
            " --data-dir " + Quote(dataFolder) + " --overlay " + Quote(overlay) +
            " --overlay-template " + Quote(Path.Combine(runtime, "overlay-template.mpq")) +
            " --asset-db " + Quote(Path.Combine(runtime, "asset_translations.json"))) {
            WorkingDirectory = stage, UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true
        };
        using (Process translator = new Process())
        {
            PatchProgress.Report("게임을 번역하고 있습니다.");
            translator.StartInfo = start;
            translator.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs line) {
                if (line.Data == null) return;
                lock (errors) { if (errors.Length < 4096) errors.AppendLine(line.Data.Substring(0, Math.Min(line.Data.Length, 4096 - errors.Length))); }
            };
            if (!translator.Start()) throw new IOException("Translator did not start.");
            translator.BeginErrorReadLine();
            Stopwatch workTime = Stopwatch.StartNew();
            bool dataStage = false;
            while (!translator.WaitForExit(250))
            {
                if (!dataStage && File.Exists(output + ".translation.json"))
                {
                    dataStage = true;
                    PatchProgress.Report("게임 데이터를 번역하고 있습니다.");
                }
                if (workTime.ElapsedMilliseconds >= 180000)
                {
                    StopTranslator(translator);
                    throw new TimeoutException("Translator timeout.");
                }
            }
            translator.WaitForExit();
            if (translator.ExitCode != 0 || !File.Exists(output))
                throw new IOException("Translator failed: " + errors.ToString());
        }
    }

    static void StopTranslator(Process translator)
    {
        // 단일 파일 런타임이 만든 자식 프로세스도 함께 종료합니다.
        using (Process stopper = Process.Start(new ProcessStartInfo(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "taskkill.exe"),
            "/PID " + translator.Id + " /T /F") {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        }))
        {
            if (stopper == null || !stopper.WaitForExit(10000))
                throw new IOException("Translator process tree did not stop.");
        }
        if (!translator.WaitForExit(5000)) throw new IOException("Translator did not stop after timeout.");
    }

    static string TranslationDigest(string runtime)
    {
        string dictionary = Path.Combine(runtime, "translations.json");
        if (File.Exists(dictionary)) return Hash(dictionary);
        using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("translation-runtime.zip"))
        using (var zip = new ZipArchive(resource, ZipArchiveMode.Read))
        {
            ZipArchiveEntry entry = zip.GetEntry("translations.json");
            if (entry == null) throw new InvalidDataException("Translator dictionary resource missing.");
            using (Stream input = entry.Open())
            using (SHA256 sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToLowerInvariant();
        }
    }

    static string Quote(string path) { return "\"" + path + "\""; }

    static ushort NativeMachine(string path)
    {
        using (var reader = new BinaryReader(File.OpenRead(path)))
        {
            Stream stream = reader.BaseStream;
            if (stream.Length < 256 || reader.ReadUInt16() != 0x5a4d) throw new UserError("게임 실행 파일을 확인해 주세요.");
            stream.Position = 0x3c;
            long header = reader.ReadUInt32();
            if (header < 64 || header > stream.Length - 128) throw new InvalidDataException("Native PE header.");
            stream.Position = header;
            if (reader.ReadUInt32() != 0x4550) throw new InvalidDataException("Native PE signature.");
            ushort machine = reader.ReadUInt16();
            stream.Position = header + 20;
            ushort optionalSize = reader.ReadUInt16();
            long optional = header + 24;
            stream.Position = optional;
            ushort magic = reader.ReadUInt16();
            int directories = magic == 0x20b ? 112 : magic == 0x10b ? 96 : 0;
            if (directories == 0 || optionalSize < directories || optional + optionalSize > stream.Length)
                throw new InvalidDataException("Native PE optional header.");
            stream.Position = optional + directories - 4;
            uint count = reader.ReadUInt32();
            if (count > 14)
            {
                if (optionalSize < directories + 15 * 8) throw new InvalidDataException("Native PE directories.");
                stream.Position = optional + directories + 14 * 8;
                if (reader.ReadUInt32() != 0 || reader.ReadUInt32() != 0) throw new InvalidDataException("Managed input is not a native game.");
            }
            return machine;
        }
    }

    static InstalledState ReadState(string folder)
    {
        try
        {
            string path = Path.Combine(folder, "installed.json");
            if (!File.Exists(path) || new FileInfo(path).Length > 4096) return null;
            var data = new JavaScriptSerializer().DeserializeObject(File.ReadAllText(path)) as Dictionary<string, object>;
            if (data == null || !data.ContainsKey("schema")) return null;
            int schema = Convert.ToInt32(data["schema"]);
            if (schema != 1 && schema != 2) return null;
            object independent;
            if (schema == 1 && (!data.TryGetValue("game_independent", out independent) || !(independent is bool) || !(bool)independent)) return null;
            object restored;
            if (!data.TryGetValue("restored", out restored) || !(restored is bool)) return null;
            var state = new InstalledState { Version = Convert.ToString(data["version"]), SourceHash = Digest(data, "source_sha256"),
                PatchedHash = Digest(data, "patched_exe_sha256"), TranslationHash = Digest(data, "translations_sha256"),
                OverlayHash = Digest(data, "overlay_sha256"), SourceBackup = Convert.ToString(data["source_backup"]), Restored = (bool)restored };
            new Version(state.Version);
            if (String.IsNullOrEmpty(state.SourceBackup)) return null;
            return state;
        }
        catch { return null; }
    }

    static string Digest(Dictionary<string, object> data, string key)
    {
        object raw;
        if (!data.TryGetValue(key, out raw)) throw new InvalidDataException(key);
        string value = Convert.ToString(raw);
        if (value.Length != 64) throw new InvalidDataException(key);
        foreach (char c in value) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) throw new InvalidDataException(key);
        return value;
    }

    static bool InstallLauncher(string folder, string backupDir, InstalledState state)
    {
        Directory.CreateDirectory(backupDir);
        string launcher = Path.Combine(folder, "AzerothSurvivors_KoreanLauncher.exe");
        string next = Path.Combine(folder, ".launcher-next-" + Guid.NewGuid().ToString("N") + ".exe");
        string previous = Path.Combine(folder, ".launcher-old-" + Guid.NewGuid().ToString("N") + ".exe");
        string pending = Path.Combine(backupDir, "launcher.pending.exe");
        string pendingBefore = Path.Combine(backupDir, ".launcher-before-" + Guid.NewGuid().ToString("N") + ".exe");
        bool hadPending = File.Exists(pending);
        bool movedOld = false, installed = false, pendingChanged = false, committed = false, preserveRecovery = false;
        try
        {
            using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream("launcher.exe"))
            using (var output = new FileStream(next, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                if (input == null) throw new InvalidDataException("Missing launcher resource.");
                input.CopyTo(output);
            }
            if (hadPending) File.Copy(pending, pendingBefore);
            bool needsReplacement = !File.Exists(launcher) || Hash(launcher) != Hash(next);
            bool defer = false;
            if (needsReplacement && File.Exists(launcher))
            {
                // 실행 중인 실행기는 교체가 막혀도 이름 변경이 가능할 수 있습니다.
                try { File.Move(launcher, previous); movedOld = true; }
                catch (IOException) { defer = true; }
                catch (UnauthorizedAccessException) { defer = true; }
            }
            if (defer)
            {
                if (hadPending) File.Replace(next, pending, null);
                else File.Move(next, pending);
                pendingChanged = true;
            }
            else
            {
                if (needsReplacement) { File.Move(next, launcher); installed = true; }
                if (hadPending) { File.Delete(pending); pendingChanged = true; }
            }
            WriteState(backupDir, state, false, defer);
            committed = true;
            return defer;
        }
        catch (Exception failure)
        {
            Exception recoveryError = null;
            try
            {
                if (installed && File.Exists(launcher)) File.Delete(launcher);
                if (movedOld) File.Move(previous, launcher);
            }
            catch (Exception recovery) { recoveryError = recovery; }
            try
            {
                if (pendingChanged)
                {
                    if (hadPending)
                    {
                        if (File.Exists(pending)) File.Replace(pendingBefore, pending, null);
                        else File.Move(pendingBefore, pending);
                    }
                    else if (File.Exists(pending)) File.Delete(pending);
                }
            }
            catch (Exception recovery) { recoveryError = recovery; }
            if (recoveryError != null)
            {
                preserveRecovery = true;
                throw new IOException("Launcher rollback failed; previous=" + previous + "; pendingBefore=" + pendingBefore,
                    new AggregateException(failure, recoveryError));
            }
            throw;
        }
        finally
        {
            if (!preserveRecovery)
            {
                DeleteTemporary(next);
                DeleteTemporary(pendingBefore);
                if (committed) DeleteTemporary(previous);
            }
        }
    }

    static void WriteState(string backupDir, InstalledState installed, bool restored, bool launcherPending = false)
    {
        Directory.CreateDirectory(backupDir);
        string state = Path.Combine(backupDir, "installed.json");
        string pending = Path.Combine(backupDir, ".installed-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(pending, new JavaScriptSerializer().Serialize(new {
                schema = 1, game_independent = true, version = PatchVersion, restored = restored,
                source_sha256 = installed.SourceHash, patched_exe_sha256 = installed.PatchedHash,
                translations_sha256 = installed.TranslationHash, overlay_sha256 = installed.OverlayHash,
                source_backup = installed.SourceBackup, launcher_pending = launcherPending
            }), new UTF8Encoding(false));
            if (File.Exists(state)) File.Replace(pending, state, null);
            else File.Move(pending, state);
        }
        finally { DeleteTemporary(pending); }
    }

    static void DeleteStage(string stage, string folder)
    {
        string parent = Path.GetDirectoryName(Path.GetFullPath(stage));
        if (!String.Equals(parent, Path.GetFullPath(folder), StringComparison.OrdinalIgnoreCase) ||
            !Path.GetFileName(stage).StartsWith(".azeroth-ko-stage-", StringComparison.Ordinal)) return;
        try { Directory.Delete(stage, true); } catch { }
    }

    static string InstallMessage(bool pending)
    {
        return pending ? "설치가 완료되었습니다.\n실행기를 종료하고 설치기를 한 번 더 실행해 주세요."
            : "설치가 완료되었습니다.\nAzerothSurvivors_KoreanLauncher.exe로 실행해 주세요.";
    }

    static void DeleteTemporary(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    static void CheckGameStopped()
    {
        foreach (Process process in Process.GetProcessesByName("AzerothSurvivors"))
        {
            using (process)
                if (!process.HasExited)
                    throw new UserError("게임을 종료하고 다시 실행해 주세요.");
        }
    }

    static string Hash(string path)
    {
        using (var stream = File.OpenRead(path))
        using (var sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }

    static void Extract(ZipArchiveEntry entry, string path)
    {
        if (entry == null) throw new InvalidDataException("설치기 데이터가 손상되었습니다.");
        using (Stream input = entry.Open())
        using (var output = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None)) input.CopyTo(output);
    }

    static void Tell(string text, bool quiet)
    {
        PatchProgress.Close();
        if (quiet) Console.WriteLine(text);
        else MessageBox.Show(text, Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}
