using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

internal static class SupportedGame
{
    const long MaximumSize = 256L * 1024 * 1024;
    const long MaximumCompressedSize = 64L * 1024 * 1024;
    sealed class Source { internal long Size, CompressedSize; internal string Hash, CompressedHash; }

    internal static void PrepareSource(string destination, string expectedHash)
    {
        string json;
        using (Stream resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("source-game.json"))
        {
            if (resource == null) throw new InvalidDataException("Missing supported game metadata.");
            if (resource.Length <= 0 || resource.Length > 4096) throw new InvalidDataException("Supported game metadata size.");
            using (StreamReader reader = new StreamReader(resource, new UTF8Encoding(false, true))) json = reader.ReadToEnd();
        }
        PrepareSource(destination, expectedHash, json,
            delegate { return Assembly.GetExecutingAssembly().GetManifestResourceStream("source-game.gz"); });
    }

    internal static void PrepareSource(string destination, string expectedHash, string json, Func<Stream> open)
    {
        Source source = Parse(json, expectedHash);
        bool created = false, complete = false;
        byte[] buffer = new byte[65536];
        try
        {
            using (Stream input = open())
            {
                if (input == null || !input.CanRead || !input.CanSeek || input.Length != source.CompressedSize)
                    throw new InvalidDataException("Supported game compressed size.");
                input.Position = 0;
                using (SHA256 sha = SHA256.Create())
                {
                    long size = Copy(input, null, buffer, source.CompressedSize, sha);
                    if (size != source.CompressedSize || Hex(sha.Hash) != source.CompressedHash)
                        throw new InvalidDataException("Supported game compressed integrity.");
                }
                input.Position = 0;
                using (GZipStream gzip = new GZipStream(input, CompressionMode.Decompress))
                using (SHA256 sha = SHA256.Create())
                using (FileStream output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    created = true;
                    long size = Copy(gzip, output, buffer, source.Size, sha);
                    if (size != source.Size || Hex(sha.Hash) != source.Hash)
                        throw new InvalidDataException("Supported game integrity.");
                    output.Flush(true);
                }
            }
            complete = true;
        }
        finally
        {
            if (created && !complete) { try { File.Delete(destination); } catch { } }
        }
    }

    static long Copy(Stream input, Stream output, byte[] buffer, long limit, SHA256 sha)
    {
        long size = 0;
        int count;
        while ((count = input.Read(buffer, 0, buffer.Length)) != 0)
        {
            size += count;
            if (size > limit) throw new InvalidDataException("Supported game size limit.");
            sha.TransformBlock(buffer, 0, count, buffer, 0);
            if (output != null) output.Write(buffer, 0, count);
        }
        sha.TransformFinalBlock(new byte[0], 0, 0);
        return size;
    }

    static Source Parse(string json, string expectedHash)
    {
        if (json == null || json.Length == 0 || json.Length > 4096) throw new InvalidDataException("Source metadata size.");
        if (expectedHash == null || !Regex.IsMatch(expectedHash, "^[a-fA-F0-9]{64}$")) throw new InvalidDataException("Expected source hash.");
        var serializer = new JavaScriptSerializer { MaxJsonLength = 4096, RecursionLimit = 10 };
        var data = serializer.Deserialize<Dictionary<string, object>>(json);
        string version = Text(data, "version");
        if (version.Length > 64 || !Regex.IsMatch(version, @"^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$")) throw new InvalidDataException("Source version.");
        Source source = new Source {
            Size = Size(data, "size", MaximumSize), Hash = Hash(data, "sha256"),
            CompressedSize = Size(data, "compressed_size", MaximumCompressedSize), CompressedHash = Hash(data, "compressed_sha256")
        };
        if (source.Hash != expectedHash.ToLowerInvariant()) throw new InvalidDataException("Source metadata does not match installer.");
        return source;
    }

    static string Text(Dictionary<string, object> data, string key)
    {
        object value;
        if (data == null || !data.TryGetValue(key, out value) || !(value is string)) throw new InvalidDataException(key);
        return (string)value;
    }
    static long Size(Dictionary<string, object> data, string key, long maximum)
    {
        object value;
        if (data == null || !data.TryGetValue(key, out value) || !(value is int || value is long)) throw new InvalidDataException(key);
        long size = Convert.ToInt64(value);
        if (size <= 0 || size > maximum) throw new InvalidDataException(key);
        return size;
    }
    static string Hash(Dictionary<string, object> data, string key)
    {
        string hash = Text(data, key);
        if (!Regex.IsMatch(hash, "^[a-fA-F0-9]{64}$")) throw new InvalidDataException(key);
        return hash.ToLowerInvariant();
    }
    static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
}
