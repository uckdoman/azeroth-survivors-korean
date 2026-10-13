using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: AssemblyVersion("0.71.4.13")]
internal static class Rollback
{
    const string Original = "f497c0589920e2fdd8c84d89b6602592bd7c609dccd55b39ea27578cc10f495a";
    const string Blocked = "1de76826e449fa8c3a745f5c53b1af47bab8c29c66155c67cb27b5ff4d1bbc75";
    const string Korean = "1c5f5732b6c59264421153cec08238deba005ea2e58d953fe1d63b8b30c38179";
    const string Overlay = "aba0e46a60c39064d477fe9df7ee8c5d84b06bbd8b648c126ae2dc2c362d788a";
    static string Hash(string path) { using (var input = File.OpenRead(path)) using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(input)).Replace("-", "").ToLowerInvariant(); }

    [STAThread]
    static int Main()
    {
        try
        {
            string folder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string game = Path.Combine(folder, "AzerothSurvivors.exe");
            if (!File.Exists(game)) throw new IOException("롤백 파일을 게임 폴더에 넣고 실행해 주세요.");
            foreach (Process process in Process.GetProcessesByName("AzerothSurvivors"))
            using (process) { throw new IOException("게임을 종료하고 다시 실행해 주세요."); }
            using (var gate = new FileStream(Path.Combine(folder, ".azeroth-ko-install.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose))
            {
                string current = Hash(game);
                string data = Path.Combine(folder, ".azeroth-ko");
                Directory.CreateDirectory(data);
                File.SetAttributes(data, File.GetAttributes(data) | FileAttributes.Hidden);
                string sourceHash = Original;
                string diskSource = null;
                string version = "0.71.4.13";
                string ownedOverlay = Overlay;
                string statePath = Path.Combine(data, "installed.json");
                if (File.Exists(statePath))
                {
                    var state = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(statePath, Encoding.UTF8));
                    object value;
                    if (state.TryGetValue("version", out value)) version = Convert.ToString(value);
                    if (state.TryGetValue("overlay_sha256", out value)) ownedOverlay = Convert.ToString(value);
                    string savedSource = state.ContainsKey("source_sha256") ? Convert.ToString(state["source_sha256"]) : "";
                    string savedPatched = state.ContainsKey("patched_exe_sha256") ? Convert.ToString(state["patched_exe_sha256"]) : "";
                    if (System.Text.RegularExpressions.Regex.IsMatch(savedSource, "^[a-f0-9]{64}$"))
                    {
                        if (current == savedPatched)
                        {
                            diskSource = Path.Combine(data, "source-" + savedSource.Substring(0, 16), "AzerothSurvivors.exe");
                            if (!File.Exists(diskSource) || Hash(diskSource) != savedSource) throw new IOException("현재 게임 버전의 원본을 찾지 못했습니다.");
                            sourceHash = savedSource;
                        }
                        else if (current != Blocked && current != Korean)
                        {
                            // Preserve an official game update instead of using an older backup.
                            diskSource = game;
                            sourceHash = current;
                        }
                    }
                }
                if (diskSource == null && current != Original && current != Blocked && current != Korean)
                    throw new IOException("이 게임 버전의 복원 원본을 찾지 못했습니다.");
                string raw = Path.Combine(data, ".rollback-source-" + Guid.NewGuid().ToString("N") + ".exe");
                string before = Path.Combine(data, "before-rollback-" + current.Substring(0, 16) + ".exe");
                string overlay = Path.Combine(folder, "Data", "patch-Z.MPQ");
                string movedOverlay = Path.Combine(data, "before-rollback-patch-Z.MPQ");
                bool replaced = false, moved = false;
                try
                {
                    if (diskSource != null) File.Copy(diskSource, raw);
                    else
                    {
                        using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("original-game.gz"))
                        using (var gzip = new GZipStream(resource, CompressionMode.Decompress))
                        using (var output = new FileStream(raw, FileMode.CreateNew, FileAccess.Write, FileShare.None)) gzip.CopyTo(output);
                    }
                    if (Hash(raw) != sourceHash) throw new IOException("원본 복원 파일을 읽지 못했습니다.");
                    if (File.Exists(overlay) && Hash(overlay) != ownedOverlay) throw new IOException("다른 패치가 있어 자동 복원할 수 없습니다.");
                    if (!File.Exists(before)) File.Copy(game, before);
                    if (Hash(before) != current || Hash(game) != current) throw new IOException("게임 파일이 변경되었습니다. 다시 실행해 주세요.");
                    if (File.Exists(overlay))
                    {
                        if (File.Exists(movedOverlay)) movedOverlay = Path.Combine(data, "before-rollback-" + Guid.NewGuid().ToString("N") + ".MPQ");
                        File.Move(overlay, movedOverlay);
                        moved = true;
                    }
                    if (current != sourceHash) { File.Replace(raw, game, null); replaced = true; }
                    var json = new JavaScriptSerializer();
                    string metadata = json.Serialize(new { schema = 1, version = version, game_independent = true,
                        restored = true, source_sha256 = sourceHash, patched_exe_sha256 = sourceHash,
                        overlay_sha256 = ownedOverlay, translations_sha256 = "", source_backup = "", launcher_pending = false });
                    File.WriteAllText(Path.Combine(data, "installed.json"), metadata, new UTF8Encoding(false));
                    string legacy = Path.Combine(folder, "한글패치_원본백업", "installed.json");
                    if (File.Exists(legacy)) File.WriteAllText(legacy, metadata, new UTF8Encoding(false));
                }
                catch
                {
                    if (replaced) File.Copy(before, game, true);
                    if (moved && !File.Exists(overlay)) File.Move(movedOverlay, overlay);
                    throw;
                }
                finally { if (File.Exists(raw)) File.Delete(raw); }
            }
            MessageBox.Show("현재 게임 버전의 원본으로 복원했습니다.\nAzerothSurvivors.exe로 실행해 주세요.", "아제로스 서바이버 롤백", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception error) { MessageBox.Show(error.Message, "아제로스 서바이버 롤백", MessageBoxButtons.OK, MessageBoxIcon.Error); return 1; }
    }
}
