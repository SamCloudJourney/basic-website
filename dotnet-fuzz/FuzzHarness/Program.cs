using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

static class P
{
    static readonly byte[][] Seeds =
    [
        [],
        [0],
        Encoding.UTF8.GetBytes("{}"),
        Encoding.UTF8.GetBytes("[]"),
        Encoding.UTF8.GetBytes("{\"a\":1}"),
        Encoding.UTF8.GetBytes("127.0.0.1"),
        Encoding.UTF8.GetBytes("::1"),
        Encoding.UTF8.GetBytes("text/plain; charset=utf-8"),
        Encoding.UTF8.GetBytes("bytes=0-1"),
        Encoding.UTF8.GetBytes("/a/%2e%2e/b?x=%ff"),
        Encoding.UTF8.GetBytes("--AaB03x\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n1\r\n--AaB03x--\r\n"),
        [0x50,0x4b,0x03,0x04,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    ];

    static int candidates;
    static string outDir = ".";

    static async Task<int> Main(string[] args)
    {
        string surface = args.ElementAtOrDefault(0) ?? "runtime";
        int iterations = int.TryParse(args.ElementAtOrDefault(1), out int n) ? n : 30000;
        int seed = int.TryParse(args.ElementAtOrDefault(2), out int s) ? s : 1337;
        outDir = args.ElementAtOrDefault(3) ?? ".";
        Directory.CreateDirectory(outDir);

        var rng = new Random(seed);
        for (int i = 0; i < iterations; i++)
        {
            byte[] data = Mutate(rng, Seeds[rng.Next(Seeds.Length)]);
            if (surface.Equals("runtime", StringComparison.OrdinalIgnoreCase))
                FuzzRuntime(data, i);
            else
                await FuzzAspNetCore(data, i);
        }

        File.WriteAllText(Path.Combine(outDir, "summary.txt"),
            $"surface={surface}\niterations={iterations}\nseed={seed}\ncandidates={candidates}\n");
        Console.WriteLine($"FUZZ_DONE surface={surface} iterations={iterations} candidates={candidates}");
        return candidates == 0 ? 0 : 2;
    }

    static byte[] Mutate(Random r, byte[] seed)
    {
        byte[] d = seed.ToArray();
        for (int k = 0; k < r.Next(1, 12); k++)
        {
            switch (r.Next(7))
            {
                case 0 when d.Length > 0:
                    d[r.Next(d.Length)] ^= (byte)(1 << r.Next(8)); break;
                case 1 when d.Length > 0:
                    d[r.Next(d.Length)] = (byte)r.Next(256); break;
                case 2 when d.Length < 16384:
                {
                    int p=r.Next(d.Length+1), add=r.Next(1, Math.Min(128,16384-d.Length)+1);
                    byte[] n=new byte[d.Length+add];
                    Buffer.BlockCopy(d,0,n,0,p); r.NextBytes(n.AsSpan(p,add));
                    Buffer.BlockCopy(d,p,n,p+add,d.Length-p); d=n; break;
                }
                case 3 when d.Length > 1:
                {
                    int p=r.Next(d.Length), del=r.Next(1,Math.Min(128,d.Length-p)+1);
                    d=d[..p].Concat(d[(p+del)..]).ToArray(); break;
                }
                case 4 when d.Length > 0 && d.Length < 16384:
                {
                    int p=r.Next(d.Length), len=Math.Min(r.Next(1,129),d.Length-p);
                    d=d.Concat(d.AsSpan(p,len).ToArray()).Take(16384).ToArray(); break;
                }
                case 5:
                {
                    byte[] x=[0,255,127,128,47,92,37,58,13,10,34,39];
                    if (d.Length==0) d=[x[r.Next(x.Length)]];
                    else d[r.Next(d.Length)]=x[r.Next(x.Length)];
                    break;
                }
                default: Array.Reverse(d); break;
            }
        }
        return d;
    }

    static string Text(byte[] d) => Encoding.UTF8.GetString(d);

    static void FuzzRuntime(byte[] d, int i)
    {
        string s=Text(d);
        NoThrow("IPAddress.TryParse",i,d,()=>_ = IPAddress.TryParse(s,out _));
        NoThrow("Uri.TryCreate",i,d,()=>_ = Uri.TryCreate(s,UriKind.RelativeOrAbsolute,out _));
        NoThrow("Base64.TryFrom",i,d,()=>{
            char[] c=s.ToCharArray(); byte[] o=new byte[Math.Max(4,c.Length*3/4+8)];
            _=Convert.TryFromBase64Chars(c,o,out _);
        });
        Expected("JsonDocument.Parse",i,d,()=>{
            using var j=JsonDocument.Parse((ReadOnlyMemory<byte>)d); _=j.RootElement.ValueKind;
        }, typeof(JsonException), typeof(ArgumentException));
        try {
            var r=new Utf8JsonReader(d,new JsonReaderOptions{MaxDepth=64,CommentHandling=JsonCommentHandling.Skip});
            while(r.Read()) if(r.TokenType==JsonTokenType.String) _=r.ValueTextEquals("fuzz"u8);
        } catch(Exception e) when(e is JsonException or ArgumentException) {}
          catch(Exception e){Save(i,d,"Utf8JsonReader",e);}
        Expected("ZipArchive",i,d,()=>{
            using var ms=new MemoryStream(d,false); using var z=new ZipArchive(ms,ZipArchiveMode.Read);
            foreach(var e in z.Entries.Take(64)){ _=e.FullName; _=e.Length; using var es=e.Open(); Span<byte> b=stackalloc byte[128]; _=es.Read(b);}
        }, typeof(InvalidDataException), typeof(IOException), typeof(NotSupportedException), typeof(ArgumentException));
        NoThrow("UTF8.GetString",i,d,()=>_=Encoding.UTF8.GetString(d));
        Expected("Type.GetType",i,d,()=>_=Type.GetType(s,false,false),
            typeof(ArgumentException),typeof(TypeLoadException),typeof(FileLoadException),typeof(FileNotFoundException));
        NoThrow("HttpRequestHeaders.TryAddWithoutValidation",i,d,()=>{
            using var req=new HttpRequestMessage(); _=req.Headers.TryAddWithoutValidation("X-Fuzz",s);
        });
    }

    static async Task FuzzAspNetCore(byte[] d, int i)
    {
        string s=Text(d);
        NoThrow("MediaTypeHeaderValue.TryParse",i,d,()=>_=Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(s,out _));
        NoThrow("ContentDispositionHeaderValue.TryParse",i,d,()=>_=Microsoft.Net.Http.Headers.ContentDispositionHeaderValue.TryParse(s,out _));
        NoThrow("EntityTagHeaderValue.TryParse",i,d,()=>_=Microsoft.Net.Http.Headers.EntityTagHeaderValue.TryParse(s,out _));
        NoThrow("RangeHeaderValue.TryParse",i,d,()=>_=Microsoft.Net.Http.Headers.RangeHeaderValue.TryParse(s,out _));
        Expected("QueryHelpers.ParseQuery",i,d,()=>_=QueryHelpers.ParseQuery(s),typeof(ArgumentException),typeof(InvalidOperationException));
        Expected("PathString.FromUriComponent",i,d,()=>_=PathString.FromUriComponent(s),typeof(ArgumentException),typeof(UriFormatException),typeof(InvalidOperationException));
        string boundary=Boundary(d);
        try {
            using var ms=new MemoryStream(d,false);
            var mr=new MultipartReader(boundary,ms){HeadersCountLimit=64,HeadersLengthLimit=32768,BodyLengthLimit=1048576};
            for(int n=0;n<8;n++){var sec=await mr.ReadNextSectionAsync();if(sec is null)break;byte[] b=new byte[256];_=await sec.Body.ReadAsync(b);}
        } catch(Exception e) when(e is InvalidDataException or IOException or ArgumentException or InvalidOperationException or FormatException) {}
          catch(Exception e){Save(i,d,"MultipartReader",e);}
    }

    static string Boundary(byte[] d)
    {
        const string a="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()+_,-./:=?";
        if(d.Length==0)return "fuzz";
        var sb=new StringBuilder(); foreach(byte b in d.Take(64)) sb.Append(a[b%a.Length]);
        return sb.ToString();
    }

    static void NoThrow(string op,int i,byte[] d,Action a){try{a();}catch(Exception e){Save(i,d,op,e);}}
    static void Expected(string op,int i,byte[] d,Action a,params Type[] ok)
    {
        try{a();}catch(Exception e){if(!ok.Any(t=>t.IsInstanceOfType(e)))Save(i,d,op,e);}
    }
    static void Save(int i,byte[] d,string op,Exception e)
    {
        int id=Interlocked.Increment(ref candidates); string stem=$"candidate-{id:D4}-{i:D7}";
        File.WriteAllBytes(Path.Combine(outDir,stem+".bin"),d);
        File.WriteAllText(Path.Combine(outDir,stem+".txt"),$"operation={op}\niteration={i}\nexception={e.GetType().FullName}\n{e}\n");
        Console.WriteLine($"CANDIDATE operation={op} exception={e.GetType().FullName} iteration={i}");
    }
}
