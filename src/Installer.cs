using System;
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
[assembly: AssemblyVersion("0.71.0.1")]

internal static class Installer
{
    const string OriginalHash = "180dd51036e9c0c6b60a27e39869e80b8397a6d2ea0a73fc8c57ee3dd7b7f22f";
    const string PatchedHash = "6cc6aeb6c9b1f58f23997eb5b9f5c3f791c3ae310b359b0e9b67d8b05bd54d68";
    const string OverlayHash = "aba0e46a60c39064d477fe9df7ee8c5d84b06bbd8b648c126ae2dc2c362d788a";
    const string AssetsHash = "49473c3cd0f47cd949e579240ea694c793aab813549920f1073ef73017364adf";
    const string Patch2Hash = "366edee41642a5dda22ed90cc252b543ee375755b7e8bee81e2a6cd59fd7b286";
    const string Title = "아제로스 서바이버 한글 패치";
    const string PatchVersion = "0.71.0.1";
    const string VersionMessage = "게임과 한글 패치가 최신 버전인지 확인해 주세요.";
    const string RetryMessage = "설치하지 못했습니다. 게임을 종료하고 다시 실행해 주세요.";
    // Add exact hashes of released Korean builds here when producing a new patch.
    static readonly string[] PreviousGameHashes = new string[0];
    static readonly string[] PreviousOverlayHashes = { "60268bcad6a3817a621a47e6f745e3a353fadf0ad85ec7f0a92b09dda1eb452f", "831eb84a21736635210f2016ec0329e263c9dab781e92bd467896072c5c87260", "3ab8c0163c5b1c00ef0e56edc9d7ebb12afe3bdc67d39a7cb1ac8e80a74c79df" };

    sealed class UserError : Exception { public UserError(string message) : base(message) { } }

    [STAThread]
    static int Main(string[] args)
    {
        bool quiet = Array.IndexOf(args, "/quiet") >= 0;
        bool restore = Array.IndexOf(args, "/restore") >= 0;
        try
        {
            string folder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string game = Path.Combine(folder, "AzerothSurvivors.exe");
            string assets = Path.Combine(folder, "Data", "patch.MPQ");
            string overlay = Path.Combine(folder, "Data", "patch-Z.MPQ");
            string backupDir = Path.Combine(folder, "한글패치_원본백업");
            string sourceDir = Path.Combine(backupDir, "source-" + OriginalHash.Substring(0, 16));
            string backup = Path.Combine(sourceDir, "AzerothSurvivors.exe");
            if (!File.Exists(game) || !File.Exists(assets))
                throw new UserError("설치기를 게임 폴더에 넣고 다시 실행해 주세요.");
            using (var installLock = new FileStream(Path.Combine(folder, ".azeroth-ko-install.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose))
            {
                CheckGameStopped();
                string current = Hash(game);
                bool knownPatched = current == PatchedHash || Array.IndexOf(PreviousGameHashes, current) >= 0;
                if (current != OriginalHash && !knownPatched)
                    throw new UserError(VersionMessage);
                bool hasOverlay = File.Exists(overlay);
                string currentOverlayHash = hasOverlay ? Hash(overlay) : null;
                if (hasOverlay && currentOverlayHash != OverlayHash && Array.IndexOf(PreviousOverlayHashes, currentOverlayHash) < 0)
                    throw new UserError("다른 한글 패치가 적용되어 있습니다. 원본 게임에 다시 설치해 주세요.");
                if (knownPatched && (!File.Exists(backup) || Hash(backup) != OriginalHash))
                    throw new UserError("원본 게임에 한글 패치를 다시 설치해 주세요.");
                string patch2 = Path.Combine(folder, "Data", "patch-2.MPQ");
                if (!restore && (Hash(assets) != AssetsHash || !File.Exists(patch2) || Hash(patch2) != Patch2Hash))
                    throw new UserError(VersionMessage);
                if (current == PatchedHash && currentOverlayHash == OverlayHash && !restore)
                {
                    bool currentState = HasCurrentState(backupDir);
                    bool pendingLauncher = InstallLauncher(folder, backupDir);
                    if (quiet || !currentState || pendingLauncher)
                    {
                        Tell(InstallMessage(pendingLauncher), quiet);
                        return 0;
                    }
                    restore = MessageBox.Show("이미 한글 패치가 적용되어 있습니다.\n원본 영문판으로 복원하시겠습니까?", Title, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
                    if (!restore) return 0;
                }
                if (restore)
                {
                    if (current == OriginalHash && !hasOverlay)
                    {
                        WriteState(backupDir, true);
                        Tell("영문판으로 복원했습니다.", quiet);
                        return 0;
                    }
                    if (!File.Exists(backup) || Hash(backup) != OriginalHash)
                        throw new UserError("원본 게임에 한글 패치를 다시 설치해 주세요.");
                }
                else
                {
                    if (File.Exists(backup) && Hash(backup) != OriginalHash)
                        throw new UserError("원본 게임에 한글 패치를 다시 설치해 주세요.");
                    if (knownPatched && !File.Exists(backup))
                        throw new UserError("원본 게임에 한글 패치를 다시 설치해 주세요.");
                }
                string stage = Path.Combine(folder, ".azeroth-ko-stage-" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(stage);
                bool preserveStage = false;
                try
                {
                    string before = Path.Combine(stage, "before.exe");
                    string next = Path.Combine(stage, "next.exe");
                    string nextOverlay = Path.Combine(stage, "patch-Z.MPQ");
                    string overlayBefore = Path.Combine(stage, "overlay-before.MPQ");
                    File.Copy(game, before);
                    if (hasOverlay) File.Copy(overlay, overlayBefore);
                    if (restore) File.Copy(backup, next);
                    else
                    {
                        using (Stream payload = Assembly.GetExecutingAssembly().GetManifestResourceStream("patch.zip"))
                        using (var zip = new ZipArchive(payload, ZipArchiveMode.Read))
                        {
                            File.Copy(current == OriginalHash ? game : backup, next);
                            ApplyDelta(zip.GetEntry("game.delta"), next);
                            Extract(zip.GetEntry("patch-Z.MPQ"), nextOverlay);
                        }
                        if (Hash(next) != PatchedHash || Hash(nextOverlay) != OverlayHash)
                            throw new InvalidOperationException("패치 데이터 검증에 실패했습니다. 게임 파일은 변경하지 않았습니다.");
                        Directory.CreateDirectory(sourceDir);
                        if (!File.Exists(backup)) File.Copy(game, backup);
                        if (Hash(backup) != OriginalHash)
                            throw new InvalidOperationException("원본 백업 검증에 실패했습니다. 게임 파일은 변경하지 않았습니다.");
                        using (Stream payload = Assembly.GetExecutingAssembly().GetManifestResourceStream("patch.zip"))
                        using (var zip = new ZipArchive(payload, ZipArchiveMode.Read))
                        {
                            Extract(zip.GetEntry("FONT-LICENSE.txt"), Path.Combine(sourceDir, "FONT-LICENSE.txt"));
                            Extract(zip.GetEntry("README.txt"), Path.Combine(sourceDir, "README.txt"));
                        }
                    }
                    CheckGameStopped();
                    if (Hash(game) != current || File.Exists(overlay) != hasOverlay || (hasOverlay && Hash(overlay) != currentOverlayHash))
                        throw new InvalidOperationException("설치 도중 게임 파일이 변경되었습니다. 다시 실행해 주세요.");
                    bool gameChanged = false;
                    bool overlayMoved = false;
                    bool pendingLauncher = false;
                    string oldOverlay = Path.Combine(stage, "previous.MPQ");
                    try
                    {
                        File.Replace(next, game, null);
                        gameChanged = true;
                        if (restore && hasOverlay)
                        {
                            File.Move(overlay, oldOverlay);
                            overlayMoved = true;
                        }
                        else if (!restore && !hasOverlay)
                        {
                            File.Move(nextOverlay, overlay);
                            overlayMoved = true;
                        }
                        else if (!restore && hasOverlay && currentOverlayHash != OverlayHash)
                        {
                            File.Replace(nextOverlay, overlay, null);
                            overlayMoved = true;
                        }
                        if (Hash(game) != (restore ? OriginalHash : PatchedHash) || (!restore && Hash(overlay) != OverlayHash))
                            throw new IOException("적용 후 파일 검증에 실패했습니다.");
                        if (!restore) pendingLauncher = InstallLauncher(folder, backupDir);
                        else WriteState(backupDir, true);
                    }
                    catch
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
                        try
                        {
                            if (gameChanged) File.Replace(before, game, null);
                        }
                        catch (Exception recovery) { recoveryError = recovery; }
                        if (recoveryError != null)
                        {
                            preserveStage = true;
                            throw new IOException("Automatic rollback failed; backup=" + backup + "; stage=" + stage, recoveryError);
                        }
                        throw;
                    }
                    Tell(restore ? "영문판으로 복원했습니다." : InstallMessage(pendingLauncher), quiet);
                }
                finally
                {
                    if (!preserveStage)
                    {
                        foreach (string name in new[] { "before.exe", "next.exe", "patch-Z.MPQ", "previous.MPQ", "overlay-before.MPQ" })
                        {
                            string path = Path.Combine(stage, name);
                            try { if (File.Exists(path)) File.Delete(path); } catch { }
                        }
                        try { Directory.Delete(stage, false); } catch { }
                    }
                }
            }
            return 0;
        }
        catch (Exception error)
        {
            LogError(error);
            string message = error is UserError ? error.Message : RetryMessage;
            if (quiet) Console.Error.WriteLine(message);
            else MessageBox.Show(message, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    static bool InstallLauncher(string folder, string backupDir)
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
                // A running launcher can often be renamed even when replacing it is blocked.
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
            WriteState(backupDir, false, defer);
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

    static bool HasCurrentState(string backupDir)
    {
        try
        {
            string path = Path.Combine(backupDir, "installed.json");
            if (!File.Exists(path)) return false;
            var state = new JavaScriptSerializer().DeserializeObject(File.ReadAllText(path)) as System.Collections.Generic.Dictionary<string, object>;
            object version, source, pending, restored;
            return state != null && state.TryGetValue("version", out version) && Convert.ToString(version) == PatchVersion
                && state.TryGetValue("source_sha256", out source) && Convert.ToString(source) == OriginalHash
                && (!state.TryGetValue("launcher_pending", out pending) || !Convert.ToBoolean(pending))
                && (!state.TryGetValue("restored", out restored) || !Convert.ToBoolean(restored));
        }
        catch { return false; }
    }

    static void WriteState(string backupDir, bool restored, bool launcherPending = false)
    {
        Directory.CreateDirectory(backupDir);
        string state = Path.Combine(backupDir, "installed.json");
        string pending = Path.Combine(backupDir, ".installed-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(pending, new JavaScriptSerializer().Serialize(new {
                schema = 1, version = PatchVersion, restored = restored,
                source_sha256 = OriginalHash, source_backup = "source-" + OriginalHash.Substring(0, 16) + "/AzerothSurvivors.exe",
                launcher_pending = launcherPending
            }), new UTF8Encoding(false));
            if (File.Exists(state)) File.Replace(pending, state, null);
            else File.Move(pending, state);
        }
        finally { DeleteTemporary(pending); }
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

    static void LogError(Exception error)
    {
        try
        {
            string folder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string path = Path.Combine(folder, ".azeroth-ko-installer.log");
            File.AppendAllText(path, DateTime.UtcNow.ToString("o") + " " + error.ToString() + Environment.NewLine, new UTF8Encoding(false));
            File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Hidden);
        }
        catch { }
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

    static void ApplyDelta(ZipArchiveEntry entry, string path)
    {
        if (entry == null) throw new InvalidDataException("실행 파일 패치 데이터가 없습니다.");
        using (var reader = new BinaryReader(entry.Open()))
        using (var output = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
        {
            if (Encoding.ASCII.GetString(reader.ReadBytes(8)) != "AZSKOD01")
                throw new InvalidDataException("패치 형식이 올바르지 않습니다.");
            long oldLength = reader.ReadInt64();
            long newLength = reader.ReadInt64();
            int count = reader.ReadInt32();
            if (output.Length != oldLength || newLength < oldLength || newLength > 256 * 1024 * 1024 || count < 0 || count > 100000)
                throw new InvalidDataException("패치 파일 크기가 올바르지 않습니다.");
            output.SetLength(newLength);
            long previousEnd = 0;
            for (int i = 0; i < count; i++)
            {
                long offset = reader.ReadInt64();
                int length = reader.ReadInt32();
                if (offset < previousEnd || length <= 0 || offset > newLength - length)
                    throw new InvalidDataException("패치 범위가 올바르지 않습니다.");
                byte[] bytes = reader.ReadBytes(length);
                if (bytes.Length != length) throw new EndOfStreamException("패치 데이터가 잘렸습니다.");
                output.Position = offset;
                output.Write(bytes, 0, bytes.Length);
                previousEnd = offset + length;
            }
            if (reader.BaseStream.ReadByte() != -1) throw new InvalidDataException("예상하지 않은 패치 데이터가 있습니다.");
        }
    }

    static void Tell(string text, bool quiet)
    {
        if (quiet) Console.WriteLine(text);
        else MessageBox.Show(text, Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}
