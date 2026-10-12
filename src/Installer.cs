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
[assembly: AssemblyVersion("0.2.0.3")]

internal static class Installer
{
    const string OriginalHash = "64fa48a5cdc3afc1621a1d7ac7426f287e2b99021a8a2b50aacc360606bb903a";
    const string PatchedHash = "ac7dcf2ab4d9227754588b22c52b4cb4772f29fb58f5c948867823e6010970b0";
    const string OverlayHash = "60268bcad6a3817a621a47e6f745e3a353fadf0ad85ec7f0a92b09dda1eb452f";
    const string AssetsHash = "49473c3cd0f47cd949e579240ea694c793aab813549920f1073ef73017364adf";
    const string Title = "아제로스 서바이버 한글 패치";
    const string PatchVersion = "0.2.0.3";
    // Add exact hashes of released Korean builds here when producing a new patch.
    static readonly string[] PreviousGameHashes = new string[0];
    static readonly string[] PreviousOverlayHashes = new string[0];

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
            string backup = Path.Combine(backupDir, "AzerothSurvivors.exe");
            if (!File.Exists(game) || !File.Exists(assets))
                throw new InvalidOperationException("이 파일을 AzerothSurvivors.exe와 Data 폴더가 있는 게임 폴더에 넣고 다시 실행해 주세요.");
            using (var installLock = new FileStream(Path.Combine(folder, ".azeroth-ko-install.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose))
            {
                CheckGameStopped();
                string current = Hash(game);
                bool knownPatched = current == PatchedHash || Array.IndexOf(PreviousGameHashes, current) >= 0;
                if (current != OriginalHash && !knownPatched)
                    throw new InvalidOperationException("지원하지 않는 게임 버전입니다.\n현재 패치는 제작 시 확인한 Windows 0.2.0 실행 파일에만 적용됩니다. 게임 파일은 변경하지 않았습니다.");
                bool hasOverlay = File.Exists(overlay);
                string currentOverlayHash = hasOverlay ? Hash(overlay) : null;
                if (hasOverlay && currentOverlayHash != OverlayHash && Array.IndexOf(PreviousOverlayHashes, currentOverlayHash) < 0)
                    throw new InvalidOperationException("Data\\patch-Z.MPQ에 다른 패치 파일이 있습니다. 기존 파일을 덮어쓰지 않았습니다.");
                if (knownPatched && (!File.Exists(backup) || Hash(backup) != OriginalHash))
                    throw new InvalidOperationException("설치기로 보관한 원본 백업이 없거나 손상되었습니다. 원본 게임 파일에서 다시 적용해 주세요.");
                if (!restore && Hash(assets) != AssetsHash)
                    throw new InvalidOperationException("Data\\patch.MPQ가 제작 시 확인한 파일과 다릅니다. 다른 버전이나 자산 패치에는 적용하지 않았습니다.");
                if (current == PatchedHash && currentOverlayHash == OverlayHash && !restore)
                {
                    InstallLauncher(folder, backupDir);
                    if (quiet) return 0;
                    restore = MessageBox.Show("이미 한글 패치가 적용되어 있습니다.\n원본 영문판으로 복원하시겠습니까?", Title, MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) == DialogResult.Yes;
                    if (!restore) return 0;
                }
                if (restore)
                {
                    if (current == OriginalHash && !hasOverlay)
                    {
                        WriteState(backupDir, true);
                        Tell("이미 원본 상태입니다.", quiet);
                        return 0;
                    }
                    if (!File.Exists(backup) || Hash(backup) != OriginalHash)
                        throw new InvalidOperationException("복원에 필요한 원본 백업을 찾을 수 없거나 백업이 손상되었습니다. 게임 파일은 변경하지 않았습니다.");
                }
                else
                {
                    if (File.Exists(backup) && Hash(backup) != OriginalHash)
                        throw new InvalidOperationException("한글패치_원본백업의 실행 파일이 예상 원본과 다릅니다. 기존 백업을 덮어쓰지 않았습니다.");
                    if (knownPatched && !File.Exists(backup))
                        throw new InvalidOperationException("한글판 실행 파일은 있지만 원본 백업이 없습니다. 원본 게임 파일에서 다시 적용해 주세요.");
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
                        Directory.CreateDirectory(backupDir);
                        if (!File.Exists(backup)) File.Copy(game, backup);
                        if (Hash(backup) != OriginalHash)
                            throw new InvalidOperationException("원본 백업 검증에 실패했습니다. 게임 파일은 변경하지 않았습니다.");
                        using (Stream payload = Assembly.GetExecutingAssembly().GetManifestResourceStream("patch.zip"))
                        using (var zip = new ZipArchive(payload, ZipArchiveMode.Read))
                        {
                            Extract(zip.GetEntry("FONT-LICENSE.txt"), Path.Combine(backupDir, "FONT-LICENSE.txt"));
                            Extract(zip.GetEntry("README.txt"), Path.Combine(backupDir, "README.txt"));
                        }
                    }
                    CheckGameStopped();
                    if (Hash(game) != current || File.Exists(overlay) != hasOverlay || (hasOverlay && Hash(overlay) != currentOverlayHash))
                        throw new InvalidOperationException("설치 도중 게임 파일이 변경되었습니다. 다시 실행해 주세요.");
                    bool gameChanged = false;
                    bool overlayMoved = false;
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
                            throw new IOException("설치 실패 후 자동 복원에도 실패했습니다.\n원본 백업: " + backup + "\n작업 폴더: " + stage + "\n" + recoveryError.Message);
                        }
                        throw;
                    }
                    if (!restore) InstallLauncher(folder, backupDir);
                    else WriteState(backupDir, true);
                    Tell(restore ? "영문판으로 복원했습니다." : "한글 패치 설치가 완료되었습니다.\nAzerothSurvivors_KoreanLauncher.exe로 실행하세요.", quiet);
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
            if (quiet) Console.Error.WriteLine(error.Message);
            else MessageBox.Show(error.Message, Title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    static void InstallLauncher(string folder, string backupDir)
    {
        Directory.CreateDirectory(backupDir);
        string launcher = Path.Combine(folder, "AzerothSurvivors_KoreanLauncher.exe");
        // The stable launcher stays in place while it is running an update installer.
        if (!File.Exists(launcher))
        {
            string pendingLauncher = Path.Combine(folder, ".launcher-" + Guid.NewGuid().ToString("N") + ".exe");
            try
            {
                using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream("launcher.exe"))
                using (var output = new FileStream(pendingLauncher, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    if (input == null) throw new InvalidDataException("업데이트 실행기 데이터가 없습니다.");
                    input.CopyTo(output);
                }
                File.Move(pendingLauncher, launcher);
            }
            finally { if (File.Exists(pendingLauncher)) File.Delete(pendingLauncher); }
        }
        WriteState(backupDir, false);
    }

    static void WriteState(string backupDir, bool restored)
    {
        Directory.CreateDirectory(backupDir);
        string state = Path.Combine(backupDir, "installed.json");
        string pending = Path.Combine(backupDir, "installed.pending.json");
        File.WriteAllText(pending, new JavaScriptSerializer().Serialize(new { schema = 1, version = PatchVersion, restored = restored }), new UTF8Encoding(false));
        if (File.Exists(state)) File.Replace(pending, state, null);
        else File.Move(pending, state);
    }

    static void CheckGameStopped()
    {
        foreach (Process process in Process.GetProcessesByName("AzerothSurvivors"))
        {
            using (process)
                if (!process.HasExited)
                    throw new InvalidOperationException("실행 중인 Azeroth Survivors를 종료한 뒤 패치를 다시 실행해 주세요.");
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
