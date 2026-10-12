using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

internal static class LauncherTests
{
    private static int Passed;
    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    private static string PublicKey;
    private static RSACryptoServiceProvider TestSigner;

    private static int Main()
    {
        // A throwaway test key is generated in memory. Production signing keys are never accessed.
        using (TestSigner = new RSACryptoServiceProvider(2048))
        {
            TestSigner.PersistKeyInCsp = false;
            PublicKey = TestSigner.ToXmlString(false);
            Dictionary<string, object> payload = Payload();
            byte[] valid = Signed(payload);
            Expect(Launcher.VerifyManifest(valid, PublicKey).Version == new Version(0, 2, 0, 2), "valid RSA2048 SHA256 signed manifest");
            Dictionary<string, object> envelope = Json.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(valid));
            byte[] signature = Convert.FromBase64String((string)envelope["signature"]);
            signature[0] ^= 1;
            envelope["signature"] = Convert.ToBase64String(signature);
            Reject(delegate { Launcher.VerifyManifest(Encoding.UTF8.GetBytes(Json.Serialize(envelope)), PublicKey); }, "tampered signature");
            envelope = Json.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(valid));
            byte[] altered = Convert.FromBase64String((string)envelope["payload"]);
            altered[10] ^= 1;
            envelope["payload"] = Convert.ToBase64String(altered);
            Reject(delegate { Launcher.VerifyManifest(Encoding.UTF8.GetBytes(Json.Serialize(envelope)), PublicKey); }, "tampered payload");
            Reject(delegate { Launcher.VerifyManifest(new byte[Launcher.ManifestLimit + 1], PublicKey); }, "oversized envelope");
            payload["padding"] = new string('x', 16384);
            Reject(delegate { Launcher.VerifyManifest(Signed(payload), PublicKey); }, "oversized signed payload");
            payload.Remove("padding");
            foreach (string url in new string[] { "http://github.com/uckdoman/azeroth-survivors-korean/releases/download/v1/AzerothSurvivors_KoreanPatch.exe", "https://github.com/other/repo/releases/download/v1/AzerothSurvivors_KoreanPatch.exe", "https://github.com.evil.test/uckdoman/azeroth-survivors-korean/releases/download/v1/AzerothSurvivors_KoreanPatch.exe", "https://github.com/uckdoman/azeroth-survivors-korean/releases/download/v1/AzerothSurvivors_KoreanPatch.exe?x=1", "https://user@github.com/uckdoman/azeroth-survivors-korean/releases/download/v1/AzerothSurvivors_KoreanPatch.exe", "https://release-assets.githubusercontent.com/file.exe" })
            {
                payload["installer_url"] = url;
                Reject(delegate { Launcher.VerifyManifest(Signed(payload), PublicKey); }, "reject installer URL " + url);
            }
            payload = Payload();
            payload["installer_size"] = Launcher.InstallerLimit + 1;
            Reject(delegate { Launcher.VerifyManifest(Signed(payload), PublicKey); }, "installer exceeds updater size limit");
            payload["installer_size"] = 0;
            Reject(delegate { Launcher.VerifyManifest(Signed(payload), PublicKey); }, "zero installer size");
            payload = Payload(); payload["installer_sha256"] = "";
            Reject(delegate { Launcher.VerifyManifest(Signed(payload), PublicKey); }, "missing required digest");
            payload = Payload(); payload["schema"] = 2;
            Reject(delegate { Launcher.VerifyManifest(Signed(payload), PublicKey); }, "unknown schema");
            Expect(!Launcher.IsNewer(new Version(0, 2, 0, 1), new Version(0, 2, 0, 2)), "downgrade refused");
            Expect(!Launcher.IsNewer(new Version(0, 2, 0, 2), new Version(0, 2, 0, 2)), "same version not reinstalled");
            FolderCases();
        }
        Console.WriteLine("PASS " + Passed + " launcher cases; no game or installer process was launched.");
        return 0;
    }

    private static void FolderCases()
    {
        string root = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "launcher-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "Data"));
        Directory.CreateDirectory(Path.Combine(root, "한글패치_원본백업"));
        try
        {
            string game = Path.Combine(root, "AzerothSurvivors.exe");
            string assets = Path.Combine(root, "Data", "patch.MPQ");
            string overlay = Path.Combine(root, "Data", "patch-Z.MPQ");
            string metadata = Path.Combine(root, "한글패치_원본백업", "installed.json");
            string installer = Path.Combine(root, "AzerothSurvivors_KoreanPatch.update.exe");
            File.WriteAllText(game, "fixture original: never an executable");
            File.WriteAllText(assets, "fixture assets");
            File.WriteAllText(installer, "fixture installer: never an executable");
            Dictionary<string, object> payload = Payload();
            payload["source_exe_sha256"] = Launcher.HashFile(game);
            payload["assets_sha256"] = Launcher.HashFile(assets);
            payload["installer_sha256"] = Launcher.HashFile(installer);
            payload["installer_size"] = new FileInfo(installer).Length;
            ReleaseInfo baseline = Launcher.VerifyManifest(Signed(payload), PublicKey);
            byte[] feed = Signed(payload);
            Func<byte[]> offline = delegate { throw new IOException("offline fixture"); };
            Expect(Launcher.Run(root, true, offline, PublicKey, baseline) == 20, "offline check-only returns20 without game launch");
            Expect(Launcher.GameValid(root, baseline), "original game hash and assets verified");
            File.WriteAllText(metadata, "{\"schema\":1,\"version\":\"0.2.0.2\"}");
            bool downloaded = false;
            Action<ReleaseInfo, string> noDownload = delegate { downloaded = true; throw new Exception("unexpected download"); };
            Expect(Launcher.Run(root, true, delegate { return feed; }, PublicKey, baseline, noDownload) == 0 && !downloaded, "current check-only skips install/download");
            File.WriteAllText(metadata, "{\"schema\":1,\"version\":\"0.2.0.3\"}");
            Expect(Launcher.Run(root, true, delegate { return feed; }, PublicKey, baseline, noDownload) == 0 && !downloaded, "installed higher version cannot downgrade");
            File.WriteAllText(metadata, "{\"schema\":1,\"version\":\"0.2.0.1\"}");
            Dictionary<string, object> incompatible = new Dictionary<string, object>(payload);
            incompatible["assets_sha256"] = new string('c', 64);
            downloaded = false;
            Expect(Launcher.Run(root, true, delegate { return Signed(incompatible); }, PublicKey, baseline, noDownload) == 26 && !downloaded, "new release for different game assets skips download with26");
            bool downloadVerified = false;
            Action<ReleaseInfo, string> fixtureDownload = delegate(ReleaseInfo release, string path) { downloadVerified = true; File.WriteAllText(path, "fixture installer: never an executable"); };
            Expect(Launcher.Run(root, true, delegate { return feed; }, PublicKey, baseline, fixtureDownload) == 10 && downloadVerified, "check-only verifies newer installer without running it");
            Expect(File.ReadAllText(metadata).Contains("0.2.0.1"), "check-only leaves installed version unchanged");
            Expect(!File.Exists(Path.Combine(root, "한글패치_원본백업", "update.cached.json")), "check-only does not commit uninstalled manifest cache");
            Action<ReleaseInfo, string> corruptDownload = delegate(ReleaseInfo release, string path) { File.WriteAllText(path, "corrupt"); };
            Expect(Launcher.Run(root, true, delegate { return feed; }, PublicKey, baseline, corruptDownload) == 21, "check-only rejects corrupt installer bytes");
            File.WriteAllText(metadata, "{\"schema\":1,\"version\":\"0.2.0.2\",\"restored\":true}");
            bool fetched = false;
            Expect(Launcher.Run(root, true, delegate { fetched = true; throw new Exception(); }, PublicKey, baseline) == 0 && !fetched, "restored original skips automatic update");
            File.WriteAllText(overlay, "unexpected overlay");
            Expect(Launcher.Run(root, true, offline, PublicKey, baseline) == 22, "restored original with unknown overlay rejected");
            File.Delete(overlay);
            File.WriteAllText(game, "fixture patched"); File.WriteAllText(overlay, "fixture Korean overlay");
            payload["patched_exe_sha256"] = Launcher.HashFile(game); payload["overlay_sha256"] = Launcher.HashFile(overlay);
            ReleaseInfo patched = Launcher.VerifyManifest(Signed(payload), PublicKey);
            Expect(Launcher.GameValid(root, patched), "patched game and overlay validated together");
            File.WriteAllText(overlay, "corrupt overlay");
            Expect(!Launcher.GameValid(root, patched), "corrupt patched overlay rejected");
            File.WriteAllText(metadata, "not json");
            Expect(Launcher.Run(root, true, offline, PublicKey, baseline) == 21, "corrupt installed metadata rejected");
        }
        finally { Directory.Delete(root, true); }
    }

    private static Dictionary<string, object> Payload()
    {
        string hash = new string('a', 64);
        return new Dictionary<string, object> { { "schema", 1 }, { "version", "0.2.0.2" }, { "installer_url", "https://github.com/uckdoman/azeroth-survivors-korean/releases/download/v0.2.0-ko.2/AzerothSurvivors_KoreanPatch.exe" }, { "installer_size", 8 }, { "installer_sha256", hash }, { "source_exe_sha256", hash }, { "patched_exe_sha256", new string('b', 64) }, { "assets_sha256", hash }, { "overlay_sha256", hash } };
    }
    private static byte[] Signed(Dictionary<string, object> data)
    {
        byte[] payload = Encoding.UTF8.GetBytes(Json.Serialize(data));
        byte[] signature = TestSigner.SignData(payload, CryptoConfig.MapNameToOID("SHA256"));
        return Encoding.UTF8.GetBytes(Json.Serialize(new Dictionary<string, object> { { "payload", Convert.ToBase64String(payload) }, { "signature", Convert.ToBase64String(signature) } }));
    }
    private static void Reject(Action action, string name)
    {
        try { action(); } catch (Exception) { Passed++; Console.WriteLine("PASS " + name); return; }
        throw new Exception("FAIL " + name);
    }
    private static void Expect(bool condition, string name)
    {
        if (!condition) throw new Exception("FAIL " + name);
        Passed++; Console.WriteLine("PASS " + name);
    }
}
