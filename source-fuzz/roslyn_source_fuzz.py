import argparse, json, random, subprocess, tempfile
from pathlib import Path

MARKERS=("Unhandled exception","Stack overflow","Fatal error","AccessViolationException","segmentation fault","core dumped","failfast","FatalExecutionEngineError")

def run(cmd,cwd,timeout):
    try:
        p=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True,errors="replace",timeout=timeout)
        t=(p.stdout or "")+"\n"+(p.stderr or "")
        return {"timeout":False,"returncode":p.returncode,"crash":any(m.lower() in t.lower() for m in MARKERS),"text":t[-20000:]}
    except subprocess.TimeoutExpired:
        return {"timeout":True,"returncode":None,"crash":False,"text":""}

def mutate(r,s,cap=20000):
    for _ in range(r.randint(1,12)):
        op=r.randrange(9)
        if op==0 and s:
            p=r.randrange(len(s)); s=s[:p]+chr(r.randrange(32,256))+s[p+1:]
        elif op==1:
            p=r.randrange(len(s)+1); ins=''.join(chr(r.choice([0,9,10,13,34,39,35,47,92,123,125,91,93,127,128,255,8238])) for _ in range(r.randint(1,48))); s=(s[:p]+ins+s[p:])[:cap]
        elif op==2 and s:
            a=r.randrange(len(s)); b=r.randrange(a,min(len(s),a+256)+1); s=s[:a]+s[b:]
        elif op==3 and s:
            a=r.randrange(len(s)); b=min(len(s),a+r.randint(1,180)); s=(s+s[a:b]*r.randint(1,10))[:cap]
        elif op==4: s=s[::-1]
        elif op==5: s=(s+r.choice(["#if X\n","#endif\n","#line 1 \"x\"\n","/*","*/","\\uD800","\\uFFFF","$$\"\"\"{{1+2}}\"\"\"","where T : class, new()","unsafe"]))[:cap]
        elif op==6: s=s.replace("{","{{").replace("}","}}")[:cap]
        elif op==7: s=(s+"<"*r.randint(1,80)+">"*r.randint(1,80))[:cap]
        else: s=(s+chr(r.randrange(32,0x10000)))[:cap]
    return s

def save(outdir,kind,i,payload,res,cmd):
    d=outdir/f"{kind}-{i:05d}"; d.mkdir(parents=True,exist_ok=True)
    (d/"input.cs").write_text(payload,encoding="utf-8",errors="surrogatepass")
    (d/"result.json").write_text(json.dumps({"kind":kind,"index":i,"cmd":cmd,"result":res},indent=2),encoding="utf-8")

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dotnet",required=True); ap.add_argument("--csc",required=True); ap.add_argument("--source",required=True); ap.add_argument("--out",required=True); ap.add_argument("--seed",type=int,default=9917); a=ap.parse_args()
    dotnet=str(Path(a.dotnet).resolve()); csc=str(Path(a.csc).resolve()); src=Path(a.source); out=Path(a.out); out.mkdir(parents=True,exist_ok=True); rng=random.Random(a.seed)
    sha=subprocess.check_output(["git","-C",str(src),"rev-parse","HEAD"],text=True).strip(); (out/"source-sha.txt").write_text(sha+"\n"); (out/"csc-path.txt").write_text(csc+"\n")
    seeds=[
      "class C { static void Main() {} }",
      "class C<T> where T:class,new() { T M<U>(U x)=>new T(); }",
      "record R(int X) { public required string S {get;init;} }",
      "#nullable enable\nfile class C { string? s; }",
      "class C { string S = $$\"\"\"{{{{1+2}}}}\"\"\"; }",
      "unsafe class C { int* p; }",
      "[System.Obsolete] class C { dynamic x; }",
      "#if X\nclass A{}\n#else\nclass B{}\n#endif",
      "class Ω { string a = \"\\uD800\"; }",
      "namespace N; partial class C { public int this[int i] => i; }",
      "class C { void M(scoped ref int x) { } }"
    ]
    work=Path(tempfile.mkdtemp(prefix="roslyn-source-fuzz-")); candidates=0; total=0
    for i in range(1200):
        total+=1; payload=mutate(rng,rng.choice(seeds)); f=work/"input.cs"; o=work/"out.dll"; f.write_text(payload,encoding="utf-8",errors="surrogatepass")
        cmd=[dotnet,csc,"/nologo","/target:library","/noconfig","/nostdlib",f"/out:{o}",str(f)]; res=run(cmd,work,8)
        if res["timeout"] or res["crash"] or (res["returncode"] is not None and res["returncode"]<0): candidates+=1; save(out,"source",i,payload,res,cmd)
    rspseeds=["/nologo\n/target:library\n/noconfig\n/nostdlib\ninput.cs\n","/langversion:preview\n/unsafe+\n/nullable:enable\ninput.cs\n","/define:A;B;C\n/warn:9999\ninput.cs\n"]
    (work/"input.cs").write_text("class C{}",encoding="utf-8")
    for i in range(400):
        total+=1; payload=mutate(rng,rng.choice(rspseeds)); rsp=work/"args.rsp"; rsp.write_text(payload,encoding="utf-8",errors="surrogatepass")
        cmd=[dotnet,csc,"@"+str(rsp)]; res=run(cmd,work,8)
        if res["timeout"] or res["crash"] or (res["returncode"] is not None and res["returncode"]<0): candidates+=1; save(out,"rsp",i,payload,res,cmd)
    (out/"summary.txt").write_text(f"source_sha={sha}\ntotal_cases={total}\ncandidates={candidates}\nseed={a.seed}\n")
    print(f"DONE total={total} candidates={candidates}")
if __name__=="__main__": main()
