using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal static class CleanupTests
{
    const string UpdateName = "AzerothSurvivors_KoreanPatch.update.exe";
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static readonly List<object> Results = new List<object>();
    static string Root;
    static int Failed;

    static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "/quiet" && args[1] == "/skip-update") return InertChild();
        if (args.Length != 2 || (args[1] != "helper" && args[1] != "timeout")) return 99;
        string allowed = Path.GetFullPath(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)) + Path.DirectorySeparatorChar;
        Root = Path.GetFullPath(args[0]);
        if (!Root.StartsWith(allowed, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Fixture outside private test directory");
        Directory.CreateDirectory(Root);
        typeof(Launcher).GetField("Quiet", BindingFlags.NonPublic | BindingFlags.Static).SetValue(null, true);
        if (args[1] == "helper")
        {
            Case("exact target deleted", delegate(string folder) { Write(folder, UpdateName, "stale"); Launcher.CleanupUpdateInstaller(folder); Require(!File.Exists(Path.Combine(folder, UpdateName)), "target remains"); });
            Case("other EXEs and state unchanged", OtherFiles);
            Case("verified FileShare.Read lock retained", delegate(string folder) { Locked(folder, FileShare.Read); });
            Case("exclusive lock retained", delegate(string folder) { Locked(folder, FileShare.None); });
            Case("cleanup after lock release", Unlocked);
            Case("absent target harmless", delegate(string folder) { Launcher.CleanupUpdateInstaller(folder); Require(Directory.GetFiles(folder).Length == 0, "created file"); });
            Case("absent folder harmless", delegate(string folder) { string missing = Path.Combine(folder, "missing"); Launcher.CleanupUpdateInstaller(missing); Require(!Directory.Exists(missing), "created folder"); });
            Case("check-only ready file retained", CheckOnlyReady);
            Case("active inert image retained then removed", ActiveImage);
            Case("exited failed child cleaned in finally", ExitedChild);
        }
        else Case("50ms fixture timeout returns25 and retains child", Timeout);
        string report = Path.Combine(Root, "report.json");
        File.WriteAllText(report, Json.Serialize(new { mode = args[1], passed = Results.Count - Failed, failed = Failed, results = Results, game_executed = false, actual_game_directory_accessed = false }), new UTF8Encoding(false));
        Console.WriteLine("TOTAL " + (Results.Count - Failed) + " PASS / " + Failed + " FAIL; " + report);
        return Failed == 0 ? 0 : 1;
    }

    static int InertChild()
    {
        string folder = Directory.GetCurrentDirectory();
        int milliseconds = Int32.Parse(File.ReadAllText(Path.Combine(folder, "fixture-child-ms.txt")));
        int exitCode = Int32.Parse(File.ReadAllText(Path.Combine(folder, "fixture-child-exit.txt")));
        File.WriteAllText(Path.Combine(folder, "fixture-child-started.txt"), "inert fixture");
        Thread.Sleep(milliseconds);
        return exitCode;
    }

    static void Case(string name, Action<string> test)
    {
        string folder = Path.Combine(Root, "case-" + (Results.Count + 1));
        Directory.CreateDirectory(folder);
        try { test(folder); Results.Add(new { name = name, passed = true }); Console.WriteLine("PASS " + name); }
        catch (Exception error) { Failed++; Results.Add(new { name = name, passed = false, error = error.ToString() }); Console.WriteLine("FAIL " + name + ": " + error.Message); }
    }

    static void Require(bool value, string message) { if (!value) throw new Exception(message); }
    static void Write(string folder, string name, string value) { string path = Path.Combine(folder, name); Directory.CreateDirectory(Path.GetDirectoryName(path)); File.WriteAllText(path, value); }
    static void ChildOptions(string folder, int milliseconds, int exitCode) { Write(folder, "fixture-child-ms.txt", milliseconds.ToString()); Write(folder, "fixture-child-exit.txt", exitCode.ToString()); }

    static void OtherFiles(string folder)
    {
        string[] names = { "AzerothSurvivors.exe", "AzerothSurvivors_KoreanPatch.exe", UpdateName + ".tmp", "other.update.exe", ".azeroth-ko/installed.json", ".azeroth-ko/update.cached.json" };
        foreach (string name in names) Write(folder, name, "unchanged:" + name);
        Write(folder, UpdateName, "stale");
        Launcher.CleanupUpdateInstaller(folder);
        Require(!File.Exists(Path.Combine(folder, UpdateName)), "target remains");
        foreach (string name in names) Require(File.ReadAllText(Path.Combine(folder, name)) == "unchanged:" + name, "sentinel changed: " + name);
        Launcher.CleanupUpdateInstaller(folder);
    }

    static void Locked(string folder, FileShare share)
    {
        string path = Path.Combine(folder, UpdateName);
        Write(folder, UpdateName, "locked sentinel");
        using (FileStream held = new FileStream(path, FileMode.Open, FileAccess.Read, share))
        {
            Launcher.CleanupUpdateInstaller(folder);
            Require(File.Exists(path), "locked target deleted");
        }
        Require(File.ReadAllText(path) == "locked sentinel", "locked bytes changed");
    }

    static void Unlocked(string folder)
    {
        string path = Path.Combine(folder, UpdateName);
        Write(folder, UpdateName, "locked sentinel");
        using (FileStream held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None)) Launcher.CleanupUpdateInstaller(folder);
        Require(File.Exists(path), "locked target deleted");
        Launcher.CleanupUpdateInstaller(folder);
        Require(!File.Exists(path), "unlocked target remains");
    }

    static byte[] SignedFixture(RSACryptoServiceProvider rsa)
    {
        string hash = Launcher.HashFile(Assembly.GetExecutingAssembly().Location);
        string zero = new string('0', 64);
        var payload = new Dictionary<string, object> {
            {"schema",1},{"version","0.71.4.11"},{"installer_url","https://github.com/uckdoman/azeroth-survivors-korean/releases/download/fixture/AzerothSurvivors_KoreanPatch.exe"},
            {"installer_size",new FileInfo(Assembly.GetExecutingAssembly().Location).Length},{"installer_sha256",hash},
            {"source_exe_sha256",zero},{"patched_exe_sha256",zero},{"assets_sha256",zero},{"overlay_sha256",zero},
            {"game_independent",true},{"translations_sha256",zero},{"runtime_sha256",zero},{"assets_translation_sha256",zero}
        };
        byte[] data = Encoding.UTF8.GetBytes(Json.Serialize(payload));
        byte[] signature = rsa.SignData(data, CryptoConfig.MapNameToOID("SHA256"));
        return Encoding.UTF8.GetBytes(Json.Serialize(new { payload = Convert.ToBase64String(data), signature = Convert.ToBase64String(signature) }));
    }

    static int RunFixture(string folder, bool checkOnly)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
        {
            rsa.PersistKeyInCsp = false;
            byte[] envelope = SignedFixture(rsa);
            return Launcher.Run(folder, checkOnly, delegate { return envelope; }, rsa.ToXmlString(false), null,
                delegate(ReleaseInfo release, string path) { File.Copy(Assembly.GetExecutingAssembly().Location, path, true); });
        }
    }

    static void CheckOnlyReady(string folder)
    {
        int result = RunFixture(folder, true);
        Require(result == 10, "check-only result=" + result);
        string path = Path.Combine(folder, UpdateName);
        Require(File.Exists(path), "ready file removed");
        Require(Launcher.HashFile(path) == Launcher.HashFile(Assembly.GetExecutingAssembly().Location), "ready bytes changed");
        Require(!File.Exists(Path.Combine(folder, "fixture-child-started.txt")), "check-only launched child");
    }

    static void ActiveImage(string folder)
    {
        string path = Path.Combine(folder, UpdateName);
        File.Copy(Assembly.GetExecutingAssembly().Location, path);
        ChildOptions(folder, 1000, 0);
        using (Process process = Process.Start(new ProcessStartInfo(path, "/quiet /skip-update") { WorkingDirectory = folder, UseShellExecute = false, CreateNoWindow = true }))
        {
            WaitForMarker(folder);
            Require(!process.HasExited, "inert child exited too early");
            Launcher.CleanupUpdateInstaller(folder);
            Require(File.Exists(path), "active image removed");
            Require(process.WaitForExit(5000), "inert child did not exit");
        }
        Launcher.CleanupUpdateInstaller(folder);
        Require(!File.Exists(path), "exited image remains");
    }

    static void WaitForMarker(string folder)
    {
        Stopwatch clock = Stopwatch.StartNew();
        while (!File.Exists(Path.Combine(folder, "fixture-child-started.txt")) && clock.ElapsedMilliseconds < 2000) Thread.Sleep(10);
        Require(File.Exists(Path.Combine(folder, "fixture-child-started.txt")), "inert child did not start");
    }

    static void ExitedChild(string folder)
    {
        ChildOptions(folder, 0, 3);
        Write(folder, ".azeroth-ko/installed.json", "{\"schema\":2,\"version\":\"0.71.4.10\"}");
        string before = File.ReadAllText(Path.Combine(folder, ".azeroth-ko/installed.json"));
        Require(RunFixture(folder, false) == 22, "failed fixture fallback result");
        Require(File.Exists(Path.Combine(folder, "fixture-child-started.txt")), "child was not exercised");
        Require(!File.Exists(Path.Combine(folder, UpdateName)), "exited failed child remains");
        Require(File.ReadAllText(Path.Combine(folder, ".azeroth-ko/installed.json")) == before, "state changed");
    }

    static void Timeout(string folder)
    {
        ChildOptions(folder, 1000, 0);
        Write(folder, ".azeroth-ko/installed.json", "{\"schema\":2,\"version\":\"0.71.4.10\"}");
        string before = File.ReadAllText(Path.Combine(folder, ".azeroth-ko/installed.json"));
        Require(RunFixture(folder, false) == 25, "timeout did not return25");
        WaitForMarker(folder);
        string path = Path.Combine(folder, UpdateName);
        Require(File.Exists(path), "timeout file deleted");
        Require(File.ReadAllText(Path.Combine(folder, ".azeroth-ko/installed.json")) == before, "state changed");
        bool sawChild = false;
        foreach (Process process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(path)))
        {
            using (process)
            {
                if (String.Equals(process.MainModule.FileName, path, StringComparison.OrdinalIgnoreCase))
                {
                    sawChild = true;
                    Require(!process.HasExited, "child already exited");
                    Require(process.WaitForExit(5000), "inert child did not exit");
                }
            }
        }
        Require(sawChild, "running timeout fixture missing");
        Require(File.Exists(path), "timeout did not preserve after child exit");
        Launcher.CleanupUpdateInstaller(folder);
        Require(!File.Exists(path), "next cleanup did not remove exited child");
    }
}
