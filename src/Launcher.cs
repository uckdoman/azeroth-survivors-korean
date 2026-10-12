using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

internal sealed class ReleaseInfo
{
    internal Version Version;
    internal string InstallerUrl, InstallerHash, SourceHash, PatchedHash, AssetsHash, OverlayHash;
    internal long InstallerSize;
}

internal static class Launcher
{
    internal const string FeedUrl = "https://github.com/uckdoman/azeroth-survivors-korean/releases/latest/download/update.json";
    internal const int ManifestLimit = 65536;
    internal const long InstallerLimit = 64L * 1024 * 1024;
    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = ManifestLimit, RecursionLimit = 8 };
    private static bool Quiet;

    // Exit codes: 0 game started / current; 10 verified update ready (check-only);
    // 11 update installed; 20 offline/check failed; 21 update failed; 22 game invalid;
    // 23 duplicate launcher; 24 invalid argument; 25 installer still running;
    // 26 newer release targets different base game assets.
    [STAThread]
    private static int Main(string[] args)
    {
        bool checkOnly = false;
        foreach (string arg in args)
        {
            if (arg == "/quiet") Quiet = true;
            else if (arg == "/check-only") checkOnly = true;
            else return 24;
        }
        string folder = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        using (Mutex gate = new Mutex(false, "Local\\AzerothSurvivorsKorean-" + HashBytes(Encoding.UTF8.GetBytes(folder.ToUpperInvariant()))))
        {
            bool owned;
            try { owned = gate.WaitOne(0); } catch (AbandonedMutexException) { owned = true; }
            if (!owned) { Notice("한글패치 실행기가 이미 실행 중입니다."); return 23; }
            try { return Run(folder, checkOnly); }
            catch (Exception) { Notice("게임을 실행하지 못했습니다. 한글 패치를 다시 설치해 주세요."); return 22; }
            finally { gate.ReleaseMutex(); }
        }
    }

    internal static int Run(string folder, bool checkOnly)
    {
        string publicKey = ReadResource("release-public-key.xml");
        ReleaseInfo baseline = ReadBaseline(ReadResource("initial-baseline.json"));
        return Run(folder, checkOnly, delegate { return DownloadBytes(new Uri(FeedUrl), ManifestLimit); }, publicKey, baseline);
    }

    internal static int Run(string folder, bool checkOnly, Func<byte[]> fetch, string publicKey, ReleaseInfo baseline, Action<ReleaseInfo, string> download = null)
    {
        if (!checkOnly && IsGameRunning(Path.Combine(folder, "AzerothSurvivors.exe"))) { Notice("게임이 이미 실행 중입니다. 게임 종료 후 다시 실행해 주세요."); return 23; }
        List<ReleaseInfo> trusted = new List<ReleaseInfo>();
        if (baseline != null) trusted.Add(baseline);
        string cache = Path.Combine(folder, "한글패치_원본백업", "update.cached.json");
        try { if (File.Exists(cache) && new FileInfo(cache).Length <= ManifestLimit) TryTrusted(File.ReadAllText(cache, Encoding.UTF8), publicKey, trusted); } catch { }
        Version installed;
        bool restored;
        try { installed = ReadInstalledVersion(folder, out restored); }
        catch { if (checkOnly) return 21; return StartExisting(folder, trusted, 21); }
        if (restored)
        {
            List<ReleaseInfo> originals = trusted.FindAll(delegate(ReleaseInfo item) { return HashFileSafe(Path.Combine(folder, "AzerothSurvivors.exe")) == item.SourceHash; });
            if (checkOnly) return GameValidAny(folder, originals) ? 0 : 22;
            return StartExisting(folder, originals, 0);
        }
        ReleaseInfo release;
        byte[] envelope;
        try
        {
            envelope = fetch();
            release = VerifyManifest(envelope, publicKey);
        }
        catch (Exception)
        {
            if (checkOnly) return 20;
            return StartExisting(folder, trusted, 20);
        }

        int result = 0;
        try
        {
            if (IsNewer(release.Version, installed))
            {
                if (HashFileSafe(Path.Combine(folder, "Data", "patch.MPQ")) != release.AssetsHash)
                {
                    if (checkOnly) return 26;
                    return StartExisting(folder, trusted, 26);
                }
                string installer = Path.Combine(folder, "AzerothSurvivors_KoreanPatch.update.exe");
                if (download == null) DownloadInstaller(release, installer);
                else download(release, installer);
                VerifyInstallerFile(release, installer);
                if (checkOnly) return 10;
                // Hold the verified file against replacement until the installer exits.
                using (FileStream hold = new FileStream(installer, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (HashStream(hold) != release.InstallerHash) throw new InvalidDataException("Installer changed");
                    using (Process process = Process.Start(new ProcessStartInfo(installer, "/quiet") { WorkingDirectory = folder, UseShellExecute = false, CreateNoWindow = true }))
                    {
                        if (!process.WaitForExit(180000)) { Notice("업데이트가 아직 진행 중입니다. 완료 후 다시 실행해 주세요."); return 25; }
                        if (process.ExitCode != 0) throw new InvalidDataException("Installer failed");
                    }
                }
                bool afterRestore;
                if (ReadInstalledVersion(folder, out afterRestore) != release.Version || afterRestore || !GameValid(folder, release)) throw new InvalidDataException("Installed files did not match");
                trusted.Add(release);
                SaveCache(cache, envelope);
                result = 11;
            }
            else
            {
                trusted.Add(release);
                if (checkOnly) return GameValidAny(folder, trusted) ? 0 : 22;
            }
        }
        catch (Exception)
        {
            if (checkOnly) return 21;
            Notice("업데이트하지 못했습니다. 현재 버전으로 실행합니다.");
            return StartExisting(folder, trusted, 21);
        }
        return StartExisting(folder, trusted, result);
    }

    internal static bool IsNewer(Version candidate, Version installed) { return candidate.CompareTo(installed) > 0; }

    internal static ReleaseInfo VerifyManifest(byte[] bytes, string publicKey)
    {
        if (bytes == null || bytes.Length == 0 || bytes.Length > ManifestLimit) throw new InvalidDataException("Manifest size");
        Dictionary<string, object> envelope = Json.Deserialize<Dictionary<string, object>>(new UTF8Encoding(false, true).GetString(bytes));
        byte[] payload = Convert.FromBase64String(Text(envelope, "payload"));
        byte[] signature = Convert.FromBase64String(Text(envelope, "signature"));
        if (payload.Length == 0 || payload.Length > 16384 || signature.Length != 256) throw new InvalidDataException("Payload size");
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            rsa.PersistKeyInCsp = false;
            rsa.FromXmlString(publicKey);
            if (rsa.KeySize != 2048 || !rsa.VerifyData(payload, CryptoConfig.MapNameToOID("SHA256"), signature)) throw new InvalidDataException("Signature");
        }
        Dictionary<string, object> data = Json.Deserialize<Dictionary<string, object>>(new UTF8Encoding(false, true).GetString(payload));
        if (Number(data, "schema") != 1) throw new InvalidDataException("Schema");
        ReleaseInfo release = new ReleaseInfo();
        release.Version = ParseVersion(Text(data, "version"));
        release.InstallerUrl = Text(data, "installer_url");
        ValidateInstallerUrl(release.InstallerUrl);
        release.InstallerSize = Number(data, "installer_size");
        if (release.InstallerSize <= 0 || release.InstallerSize > InstallerLimit) throw new InvalidDataException("Installer size");
        release.InstallerHash = Digest(data, "installer_sha256");
        release.SourceHash = Digest(data, "source_exe_sha256");
        release.PatchedHash = Digest(data, "patched_exe_sha256");
        release.AssetsHash = Digest(data, "assets_sha256");
        release.OverlayHash = Digest(data, "overlay_sha256");
        return release;
    }

    internal static void ValidateInstallerUrl(string value)
    {
        Uri uri;
        if (!Uri.TryCreate(value, UriKind.Absolute, out uri) || uri.Scheme != "https" || uri.Host != "github.com" || !uri.IsDefaultPort || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != "" ||
            !Regex.IsMatch(uri.AbsolutePath, @"^/uckdoman/azeroth-survivors-korean/releases/download/[A-Za-z0-9._-]+/AzerothSurvivors_KoreanPatch\.exe$")) throw new InvalidDataException("Installer URL");
    }

    private static HttpWebResponse OpenDownload(Uri initial, Stopwatch clock)
    {
        Uri current = initial;
        for (int hop = 0; hop < 6; hop++)
        {
            if (clock.ElapsedMilliseconds > 45000) throw new WebException("Download timeout");
            if (current.Scheme != "https" || !current.IsDefaultPort || current.UserInfo != "" || current.Fragment != "" ||
                (current.Host != "github.com" && current.Host != "release-assets.githubusercontent.com" && current.Host != "objects.githubusercontent.com")) throw new InvalidDataException("Redirect host");
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(current);
            request.AllowAutoRedirect = false;
            request.Timeout = Math.Max(1, (int)Math.Min(8000, 45000 - clock.ElapsedMilliseconds));
            request.ReadWriteTimeout = 8000;
            request.UseDefaultCredentials = false;
            request.Credentials = null;
            request.Proxy = null;
            request.UserAgent = "AzerothSurvivors-KoreanUpdater/1";
            request.AutomaticDecompression = DecompressionMethods.None;
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            int code = (int)response.StatusCode;
            if (code == 200) return response;
            string redirect = response.Headers["Location"];
            response.Close();
            if ((code != 301 && code != 302 && code != 303 && code != 307 && code != 308) || String.IsNullOrEmpty(redirect)) throw new WebException("HTTP status");
            current = new Uri(current, redirect);
        }
        throw new WebException("Too many redirects");
    }

    internal static byte[] DownloadBytes(Uri uri, int limit)
    {
        ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
        Stopwatch clock = Stopwatch.StartNew();
        using (HttpWebResponse response = OpenDownload(uri, clock))
        using (Stream input = response.GetResponseStream())
        using (MemoryStream output = new MemoryStream())
        {
            if (response.ContentLength > limit) throw new InvalidDataException("Download size");
            CopyBounded(input, output, limit, clock);
            return output.ToArray();
        }
    }

    private static void DownloadInstaller(ReleaseInfo release, string destination)
    {
        string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            Stopwatch clock = Stopwatch.StartNew();
            using (HttpWebResponse response = OpenDownload(new Uri(release.InstallerUrl), clock))
            using (Stream input = response.GetResponseStream())
            using (FileStream output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                if (response.ContentLength > release.InstallerSize) throw new InvalidDataException("Download size");
                CopyBounded(input, output, release.InstallerSize, clock);
                output.Flush(true);
            }
            VerifyInstallerFile(release, temporary);
            if (File.Exists(destination)) File.Delete(destination);
            File.Move(temporary, destination);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    internal static void VerifyInstallerFile(ReleaseInfo release, string file)
    {
        if (new FileInfo(file).Length != release.InstallerSize || HashFile(file) != release.InstallerHash) throw new InvalidDataException("Installer hash");
    }

    private static void CopyBounded(Stream input, Stream output, long limit, Stopwatch clock)
    {
        byte[] buffer = new byte[65536];
        long total = 0;
        while (true)
        {
            long remaining = 45000 - clock.ElapsedMilliseconds;
            if (remaining <= 0) throw new InvalidDataException("Download timeout");
            if (input.CanTimeout) input.ReadTimeout = Math.Max(1, (int)Math.Min(8000, remaining));
            int count = input.Read(buffer, 0, buffer.Length);
            if (clock.ElapsedMilliseconds > 45000) throw new InvalidDataException("Download timeout");
            if (count == 0) break;
            total += count;
            if (total > limit || clock.ElapsedMilliseconds > 45000) throw new InvalidDataException("Download limit");
            output.Write(buffer, 0, count);
        }
    }

    internal static bool GameValid(string folder, ReleaseInfo release)
    {
        try
        {
            string game = HashFile(Path.Combine(folder, "AzerothSurvivors.exe"));
            if (HashFile(Path.Combine(folder, "Data", "patch.MPQ")) != release.AssetsHash) return false;
            string overlay = Path.Combine(folder, "Data", "patch-Z.MPQ");
            if (game == release.PatchedHash) return File.Exists(overlay) && HashFile(overlay) == release.OverlayHash;
            return game == release.SourceHash && !File.Exists(overlay);
        }
        catch { return false; }
    }

    private static bool GameValidAny(string folder, List<ReleaseInfo> releases)
    {
        foreach (ReleaseInfo release in releases) if (GameValid(folder, release)) return true;
        return false;
    }

    private static int StartExisting(string folder, List<ReleaseInfo> trusted, int result)
    {
        FileStream installLock;
        try { installLock = new FileStream(Path.Combine(folder, ".azeroth-ko-install.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose); }
        catch { Notice("설치가 진행 중입니다. 잠시 후 다시 실행해 주세요."); return 25; }
        using (installLock)
        {
            string game = Path.Combine(folder, "AzerothSurvivors.exe");
            if (IsGameRunning(game)) { Notice("게임이 이미 실행 중입니다."); return 23; }
            if (!GameValidAny(folder, trusted)) { Notice("한글 패치를 다시 설치해 주세요."); return 22; }
            try { Process.Start(new ProcessStartInfo(game) { WorkingDirectory = folder, UseShellExecute = false }); return result; }
            catch { Notice("게임을 시작하지 못했습니다. 게임 폴더를 확인해 주세요."); return 22; }
        }
    }

    private static Version ReadInstalledVersion(string folder, out bool restored)
    {
        restored = false;
        string path = Path.Combine(folder, "한글패치_원본백업", "installed.json");
        if (!File.Exists(path)) return new Version(0, 0, 0, 0);
        if (new FileInfo(path).Length > 4096) throw new InvalidDataException("Installed metadata size");
        Dictionary<string, object> data = Json.Deserialize<Dictionary<string, object>>(File.ReadAllText(path, Encoding.UTF8));
        if (Number(data, "schema") != 1) throw new InvalidDataException("Installed schema");
        object restoreValue;
        if (data.TryGetValue("restored", out restoreValue))
        {
            if (!(restoreValue is bool)) throw new InvalidDataException("Restored metadata");
            restored = (bool)restoreValue;
        }
        return ParseVersion(Text(data, "version"));
    }

    private static ReleaseInfo ReadBaseline(string value)
    {
        Dictionary<string, object> data = Json.Deserialize<Dictionary<string, object>>(value);
        if (Number(data, "schema") != 1) throw new InvalidDataException("Baseline schema");
        return new ReleaseInfo { Version = ParseVersion(Text(data, "version")), SourceHash = Digest(data, "source_exe_sha256"), PatchedHash = Digest(data, "patched_exe_sha256"), AssetsHash = Digest(data, "assets_sha256"), OverlayHash = Digest(data, "overlay_sha256") };
    }

    private static bool IsGameRunning(string game)
    {
        foreach (Process process in Process.GetProcessesByName("AzerothSurvivors"))
        {
            using (process)
            {
                try { if (String.Equals(process.MainModule.FileName, game, StringComparison.OrdinalIgnoreCase)) return true; }
                catch { return true; }
            }
        }
        return false;
    }

    private static Version ParseVersion(string value)
    {
        if (!Regex.IsMatch(value, @"^\d{1,5}\.\d{1,5}\.\d{1,5}\.\d{1,5}$")) throw new InvalidDataException("Version");
        return new Version(value);
    }

    private static void SaveCache(string cache, byte[] envelope)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(cache));
        string temporary = cache + ".tmp";
        File.WriteAllBytes(temporary, envelope);
        if (File.Exists(cache)) File.Replace(temporary, cache, null);
        else File.Move(temporary, cache);
    }

    private static void TryTrusted(string envelope, string publicKey, List<ReleaseInfo> trusted)
    {
        try { if (!String.IsNullOrEmpty(envelope)) trusted.Add(VerifyManifest(Encoding.UTF8.GetBytes(envelope), publicKey)); } catch { }
    }
    private static string ReadResource(string name)
    {
        using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
        {
            if (stream == null) return "";
            using (StreamReader reader = new StreamReader(stream, Encoding.UTF8)) return reader.ReadToEnd();
        }
    }
    private static string Text(Dictionary<string, object> data, string key)
    {
        object value;
        if (data == null || !data.TryGetValue(key, out value) || !(value is string)) throw new InvalidDataException(key);
        return (string)value;
    }
    private static long Number(Dictionary<string, object> data, string key)
    {
        object value;
        if (data == null || !data.TryGetValue(key, out value) || !(value is int || value is long)) throw new InvalidDataException(key);
        return Convert.ToInt64(value);
    }
    private static string Digest(Dictionary<string, object> data, string key)
    {
        string value = Text(data, key);
        if (!Regex.IsMatch(value, "^[a-fA-F0-9]{64}$")) throw new InvalidDataException(key);
        return value.ToLowerInvariant();
    }
    internal static string HashFile(string file) { using (FileStream stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read)) return HashStream(stream); }
    private static string HashFileSafe(string file) { try { return HashFile(file); } catch { return ""; } }
    internal static string HashStream(Stream stream) { using (SHA256 sha = SHA256.Create()) return Hex(sha.ComputeHash(stream)); }
    private static string HashBytes(byte[] bytes) { using (SHA256 sha = SHA256.Create()) return Hex(sha.ComputeHash(bytes)); }
    private static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
    private static void Notice(string text) { if (!Quiet) MessageBox.Show(text, "AzerothSurvivors 한글패치", MessageBoxButtons.OK, MessageBoxIcon.Information); }
}
