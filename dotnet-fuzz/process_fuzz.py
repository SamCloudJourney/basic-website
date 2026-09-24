import argparse, json, os, random, shutil, subprocess, tempfile
from pathlib import Path

CRASH_MARKERS=("Unhandled exception","Stack overflow","Fatal error","AccessViolationException","segmentation fault","core dumped","failfast","FatalExecutionEngineError")

def mutate(rng,seed,cap=16384):
    s=seed
    for _ in range(rng.randint(1,10)):
        op=rng.randrange(8)
        if op==0 and s:
            p=rng.randrange(len(s)); s=s[:p]+chr(rng.randrange(0x20,0x100))+s[p+1:]
        elif op==1:
            p=rng.randrange(len(s)+1)
            ins=''.join(chr(rng.choice([0,9,10,13,34,39,37,60,62,92,0x7f,0x80,0xff,0x202e])) for _ in range(rng.randint(1,32)))
            s=(s[:p]+ins+s[p:])[:cap]
        elif op==2 and s:
            a=rng.randrange(len(s)); b=rng.randrange(a,min(len(s),a+128)+1); s=s[:a]+s[b:]
        elif op==3 and s:
            a=rng.randrange(len(s)); b=min(len(s),a+rng.randint(1,128)); s=(s+s[a:b]*rng.randint(1,8))[:cap]
        elif op==4: s=s[::-1]
        elif op==5: s=(s+rng.choice(["../","..\\","%2e%2e%2f","$(MSBuildToolsPath)","${x}","@()","*?[]","\ud800","\uffff"]))[:cap]
        elif op==6: s=s.replace("/","\\") if rng.randrange(2) else s.replace("\\","/")
        else: s=(s+chr(rng.randrange(0x20,0x10000)))[:cap]
    return s

def run(cmd,cwd,timeout,env=None):
    try:
        p=subprocess.run(cmd,cwd=cwd,env=env,capture_output=True,text=True,errors="replace",timeout=timeout)
        text=(p.stdout or "")+"\n"+(p.stderr or "")
        return {"timeout":False,"returncode":p.returncode,"crash_marker":any(m.lower() in text.lower() for m in CRASH_MARKERS),"text":text[-20000:]}
    except subprocess.TimeoutExpired:
        return {"timeout":True,"returncode":None,"crash_marker":False,"text":""}

def save(outdir,surface,idx,payload,result,cmd):
    outdir.mkdir(parents=True,exist_ok=True)
    stem=outdir/f"candidate-{idx:05d}"
    stem.with_suffix(".input.txt").write_text(payload,encoding="utf-8",errors="surrogatepass")
    stem.with_suffix(".json").write_text(json.dumps({"surface":surface,"index":idx,"result":result,"command":cmd},indent=2),encoding="utf-8")

def roslyn(n,rng,target,outdir):
    info=subprocess.check_output(["dotnet","--info"],text=True,errors="replace")
    sdk_base=next((x.split(":",1)[1].strip() for x in info.splitlines() if x.strip().startswith("Base Path:")),None)
    if not sdk_base: raise RuntimeError("no SDK Base Path")
    csc=Path(sdk_base)/"Roslyn"/"bincore"/"csc.dll"
    seeds=["class C { static void Main() {} }","class C<T> where T:class,new() { T M<U>(U x)=>new T(); }","record R(int X) { public required string S {get;init;} }","#nullable enable\nfile class C { string? s; }","class C { string S = $$\"\"\"{{{{1+2}}}}\"\"\"; }","unsafe class C { int* p; }","[System.Obsolete] class C { dynamic x; }","#if X\nclass A{}\n#else\nclass B{}\n#endif","class Ω { string a = \"\\uD800\"; }"]
    work=Path(tempfile.mkdtemp(prefix="roslyn-fuzz-")); c=0
    for i in range(n):
        src=mutate(rng,rng.choice(seeds)); f=work/"input.cs"; o=work/"out.dll"
        f.write_text(src,encoding="utf-8",errors="surrogatepass")
        cmd=["dotnet",str(csc),"/nologo","/target:library",f"/out:{o}",str(f)]; r=run(cmd,work,8)
        if r["timeout"] or r["crash_marker"] or r["returncode"] not in (0,1): c+=1; save(outdir,"roslyn",i,src,r,cmd)
    return c

def sdk(n,rng,target,outdir):
    seeds=['<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>','<Project><PropertyGroup><A>$(A)</A><B>$([System.String]::Copy(\'x\'))</B></PropertyGroup></Project>','<Project><ItemGroup><Compile Include="**/*.cs" Exclude="../**/*" /></ItemGroup></Project>','<Project><Import Project="$(MSBuildToolsPath)\\Microsoft.Common.props" Condition="Exists(\'$(MSBuildToolsPath)\\Microsoft.Common.props\')" /></Project>','<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net10.0;net9.0</TargetFrameworks><RuntimeIdentifier>win-x64</RuntimeIdentifier><PublishProfile>DefaultContainer</PublishProfile></PropertyGroup></Project>']
    work=Path(tempfile.mkdtemp(prefix="sdk-fuzz-")); c=0
    for i in range(n):
        payload=mutate(rng,rng.choice(seeds)); proj=work/"fuzz.csproj"; pp=work/"pp.xml"
        proj.write_text(payload,encoding="utf-8",errors="surrogatepass")
        if pp.exists(): pp.unlink()
        cmd=["dotnet","msbuild",str(proj),"/nologo","/v:q",f"/pp:{pp}"]; r=run(cmd,work,8)
        if r["timeout"] or r["crash_marker"] or r["returncode"] not in (0,1): c+=1; save(outdir,"sdk",i,payload,r,cmd)
    return c

def templating(n,rng,target,outdir):
    seeds=['{"$schema":"http://json.schemastore.org/template","author":"fuzz","classifications":["Test"],"identity":"Fuzz.Template","name":"Fuzz","shortName":"fuzzx","sourceName":"SOURCE"}','{"identity":"Fuzz.Template","name":"Fuzz","shortName":"fuzzx","symbols":{"p":{"type":"parameter","datatype":"string","defaultValue":"x"}}}','{"identity":"Fuzz.Template","name":"Fuzz","shortName":"fuzzx","sources":[{"modifiers":[{"exclude":["**/bin/**","../**"]}]}]}']
    home=Path(tempfile.mkdtemp(prefix="template-home-")); root=Path(tempfile.mkdtemp(prefix="template-fuzz-")); env=os.environ.copy(); env["DOTNET_CLI_HOME"]=str(home); c=0
    for i in range(n):
        t=root/"t"
        if t.exists(): shutil.rmtree(t)
        (t/".template.config").mkdir(parents=True)
        payload=mutate(rng,rng.choice(seeds))
        (t/".template.config"/"template.json").write_text(payload,encoding="utf-8",errors="surrogatepass")
        (t/"SOURCE.txt").write_text("hello SOURCE",encoding="utf-8")
        cmd=["dotnet","new","install",str(t),"--force"]; r=run(cmd,root,10,env)
        if r["timeout"] or r["crash_marker"] or (r["returncode"] is not None and r["returncode"]<0): c+=1; save(outdir,"templating",i,payload,r,cmd)
        run(["dotnet","new","uninstall",str(t)],root,5,env)
    return c

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--surface",choices=["roslyn","sdk","templating"],required=True)
    ap.add_argument("--target",required=True); ap.add_argument("--out",required=True)
    ap.add_argument("--iterations",type=int,default=150); ap.add_argument("--seed",type=int,default=1337)
    a=ap.parse_args()
    out=Path(a.out); out.mkdir(parents=True,exist_ok=True)
    sha=subprocess.check_output(["git","-C",a.target,"rev-parse","HEAD"],text=True).strip()
    (out/"source-sha.txt").write_text(sha+"\n")
    rng=random.Random(a.seed)
    fn={"roslyn":roslyn,"sdk":sdk,"templating":templating}[a.surface]
    candidates=fn(a.iterations,rng,Path(a.target),out)
    (out/"summary.txt").write_text(f"surface={a.surface}\niterations={a.iterations}\nseed={a.seed}\ncandidates={candidates}\nsource_sha={sha}\n")
    print(f"FUZZ_DONE surface={a.surface} iterations={a.iterations} candidates={candidates} sha={sha}")

if __name__=="__main__": main()
