using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;

internal static class SupportedGameTests
{
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static readonly byte[] Plain = Encoding.UTF8.GetBytes("ephemeral supported source game; never executed\n");
    static byte[] Compressed;
    static string Root;
    static int Passed;
    static string Hash(byte[] b) { using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(b)).Replace("-", "").ToLowerInvariant(); }
    static void Check(bool value, string why) { if (!value) throw new Exception(why); }
    static byte[] Gzip(byte[] input)
    {
        using (MemoryStream output = new MemoryStream())
        {
            using (GZipStream gzip = new GZipStream(output, CompressionMode.Compress, true)) gzip.Write(input, 0, input.Length);
            return output.ToArray();
        }
    }
    static Dictionary<string, object> Manifest(byte[] gzip, byte[] plain)
    {
        return new Dictionary<string, object> { { "version", "9.8.7" }, { "size", plain.Length }, { "sha256", Hash(plain) }, { "compressed_size", gzip.Length }, { "compressed_sha256", Hash(gzip) } };
    }
    static string Dest(string name) { return Path.Combine(Root, name + ".bin"); }
    static void Reject(string name, Dictionary<string, object> data, string expected, Func<Stream> open)
    {
        string output = Dest(name); bool rejected = false;
        try { SupportedGame.PrepareSource(output, expected, Json.Serialize(data), open); }
        catch (InvalidDataException) { rejected = true; }
        catch (IOException) { rejected = true; }
        catch (ArgumentException) { rejected = true; }
        Check(rejected, name + " was accepted");
        Check(!File.Exists(output), name + " left partial source"); Passed++;
    }
    static void Main(string[] args)
    {
        Root = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "supported-source-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root); Compressed = Gzip(Plain);
        SupportedGame.PrepareSource(Dest("valid"), Hash(Plain), Json.Serialize(Manifest(Compressed, Plain)), delegate { return new MemoryStream(Compressed); });
        Check(Hash(File.ReadAllBytes(Dest("valid"))) == Hash(Plain), "valid gzip did not reconstruct source"); Passed++;
        Reject("expected-mismatch", Manifest(Compressed, Plain), new string('0', 64), delegate { throw new Exception("must not open"); });
        foreach (string version in new[] { "", "../escape", "9.8", "9.8.7suffix" })
        {
            var data = Manifest(Compressed, Plain); data["version"] = version;
            Reject("invalid-version-" + Passed, data, Hash(Plain), delegate { throw new Exception("must not open"); });
        }
        foreach (string key in new[] { "size", "compressed_size" })
        {
            var data = Manifest(Compressed, Plain); data[key] = 0;
            Reject("zero-" + key, data, Hash(Plain), delegate { throw new Exception("must not open"); });
            data = Manifest(Compressed, Plain); data[key] = (key == "size" ? 256L : 64L) * 1024 * 1024 + 1;
            Reject("oversize-" + key, data, Hash(Plain), delegate { throw new Exception("must not open"); });
            data = Manifest(Compressed, Plain); data[key] = 12.5;
            Reject("fraction-" + key, data, Hash(Plain), delegate { throw new Exception("must not open"); });
        }
        foreach (string key in new[] { "sha256", "compressed_sha256" })
        {
            var data = Manifest(Compressed, Plain); data[key] = "not-a-hash";
            Reject("bad-format-" + key, data, Hash(Plain), delegate { throw new Exception("must not open"); });
        }
        Reject("missing-stream", Manifest(Compressed, Plain), Hash(Plain), delegate { return null; });
        Reject("compressed-short", Manifest(Compressed, Plain), Hash(Plain), delegate { return new MemoryStream(new byte[1]); });
        Reject("compressed-long", Manifest(Compressed, Plain), Hash(Plain), delegate { return new MemoryStream(new byte[Compressed.Length + 1]); });
        byte[] wrong = (byte[])Compressed.Clone(); wrong[wrong.Length - 1] ^= 1;
        Reject("compressed-bad-hash", Manifest(Compressed, Plain), Hash(Plain), delegate { return new MemoryStream(wrong); });
        var manifest = Manifest(Compressed, Plain); manifest["size"] = Plain.Length - 1;
        Reject("decoded-too-long", manifest, Hash(Plain), delegate { return new MemoryStream(Compressed); });
        manifest = Manifest(Compressed, Plain); manifest["size"] = Plain.Length + 1;
        Reject("decoded-too-short", manifest, Hash(Plain), delegate { return new MemoryStream(Compressed); });
        manifest = Manifest(Compressed, Plain); manifest["sha256"] = new string('0', 64);
        Reject("decoded-bad-hash", manifest, new string('0', 64), delegate { return new MemoryStream(Compressed); });
        byte[] badGzip = Encoding.UTF8.GetBytes("not a gzip file");
        Reject("invalid-gzip", Manifest(badGzip, Plain), Hash(Plain), delegate { return new MemoryStream(badGzip); });
        Reject("compressed-read-failure", Manifest(Compressed, Plain), Hash(Plain), delegate { return new FailureStream(Compressed); });

        string existing = Dest("existing"); File.WriteAllText(existing, "current source remains");
        bool blocked = false; try { SupportedGame.PrepareSource(existing, Hash(Plain), Json.Serialize(Manifest(Compressed, Plain)), delegate { return new MemoryStream(Compressed); }); } catch (IOException) { blocked = true; }
        Check(blocked && File.ReadAllText(existing) == "current source remains", "existing destination touched"); Passed++;

        if (args.Length == 2)
        {
            string json = File.ReadAllText(args[0]); var data = Json.Deserialize<Dictionary<string, object>>(json);
            string expected = (string)data["sha256"], local = Dest("local-official-resource");
            SupportedGame.PrepareSource(local, expected, json, delegate { return new FileStream(args[1], FileMode.Open, FileAccess.Read, FileShare.Read); });
            Check(new FileInfo(local).Length == Convert.ToInt64(data["size"]) && Hash(File.ReadAllBytes(local)) == expected, "local official gzip reconstruction mismatch");
            File.Delete(local); Passed++;
        }
        File.WriteAllText(Path.Combine(Root, "result.json"), Json.Serialize(new { status = "passed", cases = Passed, network_requests = 0, game_processes_started = 0, actual_game_folder_modified = false }));
        Console.WriteLine("PASS " + Passed + " supported source resource cases; no network, game execution, or real-folder changes.");
    }
    sealed class FailureStream : MemoryStream
    {
        internal FailureStream(byte[] data) : base(data) { }
        public override int Read(byte[] buffer, int offset, int count) { throw new IOException("controlled resource read failure"); }
    }
}
