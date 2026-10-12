using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Web.Script.Serialization;

internal static class InstallerUpdateTests
{
    static RSACryptoServiceProvider Signer;
    static string Key;
    static int Passed;
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
    static readonly byte[] Child = Encoding.UTF8.GetBytes("signed fixture installer: never executed");
    static readonly byte[] NextGame = Encoding.UTF8.GetBytes("controlled fixture patched game: never executed");
    static readonly byte[] NextOverlay = Encoding.UTF8.GetBytes("controlled fixture Korean overlay");
    static string Root;
    static string H(byte[] bytes) { using (SHA256 sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","").ToLowerInvariant(); }
    static void Check(bool ok, string message) { if (!ok) throw new Exception(message); }
    static string Fixture(string name)
    {
        string f=Path.Combine(Root,name);Directory.CreateDirectory(Path.Combine(f,"Data"));Directory.CreateDirectory(Path.Combine(f,"한글패치_원본백업"));
        File.WriteAllText(Path.Combine(f,"AzerothSurvivors.exe"),"unsupported local game");
        File.WriteAllText(Path.Combine(f,"Data","patch.MPQ"),"fixture base assets");
        File.WriteAllText(Path.Combine(f,"Data","patch-2.MPQ"),"fixture patch2");
        File.WriteAllText(Path.Combine(f,"Data","patch-Z.MPQ"),"old fixture overlay");
        State(f,"0.71.0.1",false);return f;
    }
    static void State(string f,string version,bool restored)
    {
        File.WriteAllText(Path.Combine(f,"한글패치_원본백업","installed.json"),Json.Serialize(new {schema=1,version=version,restored=restored}));
    }
    static Dictionary<string,object> Payload(string f,string version)
    {
        return new Dictionary<string,object> {
            {"schema",1},{"version",version},{"installer_url","https://github.com/uckdoman/azeroth-survivors-korean/releases/download/test-v2/AzerothSurvivors_KoreanPatch.exe"},
            {"installer_size",Child.Length},{"installer_sha256",H(Child)},{"source_exe_sha256",H(Encoding.UTF8.GetBytes("future source base"))},
            {"patched_exe_sha256",H(NextGame)},{"overlay_sha256",H(NextOverlay)},{"assets_sha256",Launcher.HashFile(Path.Combine(f,"Data","patch.MPQ"))},
            {"patch2_sha256",Launcher.HashFile(Path.Combine(f,"Data","patch-2.MPQ"))}
        };
    }
    static byte[] Signed(Dictionary<string,object> payload)
    {
        byte[] b=Encoding.UTF8.GetBytes(Json.Serialize(payload));byte[] sig=Signer.SignData(b,CryptoConfig.MapNameToOID("SHA256"));
        return Encoding.UTF8.GetBytes(Json.Serialize(new {payload=Convert.ToBase64String(b),signature=Convert.ToBase64String(sig)}));
    }
    static Dictionary<string,string> Snapshot(string f)
    {
        var d=new Dictionary<string,string>();foreach(string n in new[]{"AzerothSurvivors.exe","Data/patch.MPQ","Data/patch-2.MPQ","Data/patch-Z.MPQ","한글패치_원본백업/installed.json"})d[n]=Launcher.HashFile(Path.Combine(f,n));return d;
    }
    static void Unchanged(string f,Dictionary<string,string> before)
    {
        foreach(var p in before)Check(Launcher.HashFile(Path.Combine(f,p.Key))==p.Value,"current file changed: "+p.Key);
        Check(Directory.GetFiles(f,".azeroth-ko-update-*.exe").Length==0,"update temporary image left behind");
    }
    static void Reject(Action action,string message)
    {
        bool rejected=false;try{action();}catch(InstallerUpdate.UpdateError){rejected=true;}Check(rejected,message);
    }
    static void Main()
    {
        Root=Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location),"small-fixtures-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(Root);
        using(Signer=new RSACryptoServiceProvider(2048))
        {
            Signer.PersistKeyInCsp=false;Key=Signer.ToXmlString(false);
            Newer();SameOrOlder();InvalidManifest();UnsafeUrl();BadInstaller();Offline();ChildFailure();BadPostState();Notice();StillRunning();
        }
        File.WriteAllText(Path.Combine(Root,"result.json"),Json.Serialize(new {status="passed",cases=Passed,game_processes_started=0,installer_processes_started=0,private_production_key_access=false,scope="real update helper with injected fixture callbacks; caller order separately checked"}));
        Console.WriteLine("PASS "+Passed+" meaningful helper cases; no game or installer process launched; temporary RSA key stayed in memory.");
    }
    static void Newer()
    {
        string f=Fixture("newer");var p=Payload(f,"2.0.0.1");int called=0;bool locked=false;byte[] feed=Signed(p);
        Check(Launcher.HashFile(Path.Combine(f,"AzerothSurvivors.exe"))!=Convert.ToString(p["source_exe_sha256"]),"initial game must be unsupported by signed future release");
        bool ok=InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),true,delegate{return feed;},Key,
            delegate(ReleaseInfo release,string path){File.WriteAllBytes(path,Child);},
            delegate(string path,string args){
                called++;Check(args=="/quiet /skip-update","child recursion/quiet flags missing");
                using(var gate=new FileStream(Path.Combine(f,".azeroth-ko-install.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)){}
                try{File.WriteAllText(path,"replace attacker");}catch(IOException){locked=true;}Check(locked,"verified image not held against replacement");
                File.WriteAllBytes(Path.Combine(f,"AzerothSurvivors.exe"),NextGame);File.WriteAllBytes(Path.Combine(f,"Data","patch-Z.MPQ"),NextOverlay);State(f,"2.0.0.1",false);return 0;
            },delegate(ReleaseInfo release){return InstallerUpdate.InstalledMatches(f,release);},delegate(string text){throw new Exception("quiet mode must not notify");});
        Check(ok&&called==1&&locked,"new signed version did not delegate/install/validate");Check(Directory.GetFiles(f,".azeroth-ko-update-*.exe").Length==0,"verified child image not cleaned");Passed++;
    }
    static void SameOrOlder()
    {
        foreach(string ver in new[]{"0.71.0.2","0.71.0.1"}){
            string f=Fixture("not-newer-"+ver);var before=Snapshot(f);byte[] feed=Signed(Payload(f,ver));int calls=0;
            bool ok=InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),true,delegate{return feed;},Key,delegate{calls++;},delegate{calls++;return 0;},delegate{return false;},delegate{calls++;});
            Check(!ok&&calls==0,"same/older version downloaded or executed");Unchanged(f,before);Passed++;
        }
    }
    static void InvalidManifest()
    {
        string f=Fixture("bad-signature");var before=Snapshot(f);var envelope=Json.Deserialize<Dictionary<string,object>>(Encoding.UTF8.GetString(Signed(Payload(f,"2.0.0.1"))));byte[] sig=Convert.FromBase64String((string)envelope["signature"]);sig[0]^=1;envelope["signature"]=Convert.ToBase64String(sig);byte[] feed=Encoding.UTF8.GetBytes(Json.Serialize(envelope));int calls=0;
        Reject(delegate{InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),true,delegate{return feed;},Key,delegate{calls++;},delegate{calls++;return 0;},delegate{return false;},null);},"tampered signature not rejected");Check(calls==0,"tampered manifest reached execution");Unchanged(f,before);Passed++;
    }
    static void UnsafeUrl()
    {
        string f=Fixture("unsafe-url");var before=Snapshot(f);var p=Payload(f,"2.0.0.1");p["installer_url"]="https://github.com.evil.example/uckdoman/azeroth-survivors-korean/releases/download/test/AzerothSurvivors_KoreanPatch.exe";byte[] feed=Signed(p);int calls=0;
        Reject(delegate{InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),true,delegate{return feed;},Key,delegate{calls++;},delegate{calls++;return 0;},delegate{return false;},null);},"unsafe URL accepted");Check(calls==0,"unsafe URL downloaded/executed");Unchanged(f,before);Passed++;
    }
    static void BadInstaller()
    {
        string f=Fixture("tampered-installer");var before=Snapshot(f);byte[] feed=Signed(Payload(f,"2.0.0.1"));int calls=0;
        Reject(delegate{InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),true,delegate{return feed;},Key,delegate(ReleaseInfo release,string path){byte[] wrong=(byte[])Child.Clone();wrong[0]^=1;File.WriteAllBytes(path,wrong);},delegate{calls++;return 0;},delegate{return false;},null);},"tampered installer accepted");Check(calls==0,"bad installer executed");Unchanged(f,before);Passed++;
    }
    static void Offline()
    {
        string f=Fixture("offline");var before=Snapshot(f);int calls=0;
        bool ok=InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),true,delegate{throw new WebException("offline fixture");},Key,delegate{calls++;},delegate{calls++;return 0;},delegate{return false;},delegate{calls++;});
        Check(!ok&&calls==0,"offline did not return to bundled path quietly");Unchanged(f,before);Passed++;
    }
    static void ChildFailure()
    {
        string f=Fixture("child-failure");var before=Snapshot(f);byte[] feed=Signed(Payload(f,"2.0.0.1"));int post=0;
        Reject(delegate{InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),true,delegate{return feed;},Key,delegate(ReleaseInfo release,string path){File.WriteAllBytes(path,Child);},delegate{return 1;},delegate{post++;return true;},null);},"failed child accepted");Check(post==0,"postcheck ran after failed child");Unchanged(f,before);Passed++;
    }
    static void BadPostState()
    {
        string f=Fixture("bad-post-state");var before=Snapshot(f);byte[] feed=Signed(Payload(f,"2.0.0.1"));
        Reject(delegate{InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),true,delegate{return feed;},Key,delegate(ReleaseInfo release,string path){File.WriteAllBytes(path,Child);},delegate{return 0;},delegate(ReleaseInfo release){return InstallerUpdate.InstalledMatches(f,release);},null);},"zero exit accepted without installed version/hashes");Unchanged(f,before);
        ReleaseInfo verifiedRelease=Launcher.VerifyManifest(feed,Key);File.WriteAllBytes(Path.Combine(f,"AzerothSurvivors.exe"),NextGame);File.WriteAllBytes(Path.Combine(f,"Data","patch-Z.MPQ"),NextOverlay);State(f,"2.0.0.0",false);Check(!InstallerUpdate.InstalledMatches(f,verifiedRelease),"wrong installed version accepted");State(f,"2.0.0.1",true);Check(!InstallerUpdate.InstalledMatches(f,verifiedRelease),"restored state accepted");State(f,"2.0.0.1",false);File.WriteAllText(Path.Combine(f,"AzerothSurvivors.exe"),"wrong game");Check(!InstallerUpdate.InstalledMatches(f,verifiedRelease),"wrong installed game hash accepted");Passed++;
    }
    static void Notice()
    {
        string f=Fixture("normal-notice");byte[] feed=Signed(Payload(f,"2.0.0.1"));int notices=0;
        bool ok=InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),false,delegate{return feed;},Key,delegate(ReleaseInfo release,string path){File.WriteAllBytes(path,Child);},delegate{File.WriteAllBytes(Path.Combine(f,"AzerothSurvivors.exe"),NextGame);File.WriteAllBytes(Path.Combine(f,"Data","patch-Z.MPQ"),NextOverlay);State(f,"2.0.0.1",false);return 0;},delegate(ReleaseInfo release){return InstallerUpdate.InstalledMatches(f,release);},delegate(string text){notices++;Check(text.Length<100&&text.IndexOf("설치")>=0,"notice too verbose");});
        Check(ok&&notices==1,"normal update should issue one short notice");Passed++;
    }
    static void StillRunning()
    {
        string f=Fixture("child-still-running");var before=Snapshot(f);byte[] feed=Signed(Payload(f,"2.0.0.1"));int post=0;
        Reject(delegate{InstallerUpdate.TryInstallLatest(f,new Version(0,71,0,2),true,delegate{return feed;},Key,delegate(ReleaseInfo release,string path){File.WriteAllBytes(path,Child);},delegate{return InstallerUpdate.ChildStillRunning;},delegate{post++;return true;},null);},"running child did not halt old installer");
        Check(post==0,"postcheck ran while child was running");foreach(var p in before)Check(Launcher.HashFile(Path.Combine(f,p.Key))==p.Value,"timeout modified current files");
        string[] left=Directory.GetFiles(f,".azeroth-ko-update-*.exe");Check(left.Length==1&&Launcher.HashFile(left[0])==H(Child),"running child image not preserved");Passed++;
    }

}
