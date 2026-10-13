using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

internal static class InstallerUpdate
{
    internal const int ChildStillRunning = -2;

    internal sealed class UpdateError : Exception
    {
        internal UpdateError(Exception inner) : base("최신 한글 패치를 설치하지 못했습니다. 다시 실행해 주세요.", inner) { }
        internal UpdateError() : base("최신 한글 패치 설치가 진행 중입니다. 잠시 후 다시 확인해 주세요.") { }
    }

    internal static bool TryInstallLatest(string folder, Version bundledVersion, bool quiet)
    {
        string publicKey;
        using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream("release-public-key.xml"))
        {
            if (input == null) throw new UpdateError(new InvalidDataException("Missing public key resource."));
            using (StreamReader reader = new StreamReader(input, Encoding.UTF8)) publicKey = reader.ReadToEnd();
        }
        return TryInstallLatest(folder, bundledVersion, quiet,
            delegate { return Launcher.DownloadBytes(new Uri(Launcher.FeedUrl), Launcher.ManifestLimit); },
            publicKey, Launcher.DownloadInstaller, RunChild,
            delegate(ReleaseInfo release) { return InstalledMatches(folder, release); },
            delegate(string message) { PatchProgress.Report("최신 한글 패치를 내려받고 있습니다."); });
    }

    internal static bool TryInstallLatest(string folder, Version bundledVersion, bool quiet,
        Func<byte[]> fetch, string publicKey, Action<ReleaseInfo, string> download,
        Func<string, string, int> runChild, Func<ReleaseInfo, bool> postcheck, Action<string> notice)
    {
        byte[] envelope;
        try { envelope = fetch(); }
        catch (WebException) { return false; }
        catch (TimeoutException) { return false; }
        catch (InvalidDataException error)
        {
            if (error.Message == "Download timeout") return false;
            throw new UpdateError(error);
        }
        catch (IOException) { return false; }
        catch (Exception error) { throw new UpdateError(error); }

        ReleaseInfo release;
        try { release = Launcher.VerifyManifest(envelope, publicKey); }
        catch (Exception error) { throw new UpdateError(error); }
        if (!Launcher.IsNewer(release.Version, bundledVersion)) return false;

        string child = Path.Combine(folder, ".azeroth-ko-update-" + Guid.NewGuid().ToString("N") + ".exe");
        bool preserveChild = false;
        try
        {
            if (!quiet && notice != null) notice("새 한글 패치가 있습니다. 최신 버전으로 설치합니다.");
            PatchProgress.Report("최신 한글 패치를 내려받고 있습니다.");
            download(release, child);
            // Hold the verified image while launching and waiting; keep a timed-out child's file.
            using (FileStream image = new FileStream(child, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (SHA256 sha = SHA256.Create())
            {
                string digest = BitConverter.ToString(sha.ComputeHash(image)).Replace("-", "").ToLowerInvariant();
                if (image.Length != release.InstallerSize || digest != release.InstallerHash)
                    throw new InvalidDataException("Downloaded installer does not match its signed manifest.");
                PatchProgress.Report("최신 한글 패치를 설치하고 있습니다.");
                int result = runChild(child, "/quiet /skip-update");
                if (result == ChildStillRunning)
                {
                    preserveChild = true;
                    throw new UpdateError();
                }
                if (result != 0)
                    throw new InvalidOperationException("Update installer failed.");
                PatchProgress.Report("설치를 마무리하고 있습니다.");
                if (!postcheck(release)) throw new InvalidDataException("Installed update verification failed.");
            }
            return true;
        }
        catch (UpdateError) { throw; }
        catch (Exception error) { throw new UpdateError(error); }
        finally
        {
            if (!preserveChild) { try { if (File.Exists(child)) File.Delete(child); } catch { } }
        }
    }

    internal static bool InstalledMatches(string folder, ReleaseInfo release)
    {
        try
        {
            bool restored;
            Version version = Launcher.ReadInstalledVersion(folder, out restored);
            return !restored && version == release.Version && Launcher.GameValid(folder, release)
                && (release.GameIndependent || Launcher.HashFile(Path.Combine(folder, "AzerothSurvivors.exe")) == release.PatchedHash);
        }
        catch { return false; }
    }

    private static int RunChild(string installer, string arguments)
    {
        using (Process child = Process.Start(new ProcessStartInfo(installer, arguments) {
            WorkingDirectory = Path.GetDirectoryName(installer), UseShellExecute = false, CreateNoWindow = true
        }))
        {
            if (child == null) throw new InvalidOperationException("Update installer did not start.");
            if (!child.WaitForExit(180000)) return ChildStillRunning;
            return child.ExitCode;
        }
    }
}
