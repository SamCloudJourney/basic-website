import argparse, json, os, random, shutil, subprocess, tempfile
from pathlib import Path

MARKERS=("Unhandled exception","Stack overflow","Fatal error","AccessViolationException","segmentation fault","core dumped","failfast","FatalExecutionEngineError")

def run(cmd,cwd,timeout,env=None):
    try:
        p=subprocess.run(cmd,cwd=cwd,env=env,capture_output=True,text=True,errors="replace",timeout=timeout)
        t=(p.stdout or "")+"\n"+(p.stderr or "")
        return {"timeout":False,"returncode":p.returncode,"crash":any(m.lower() in t.lower() for m in MARKERS),"text":t[-20000:]}
    except subprocess.TimeoutExpired:
        return {"timeout":True,"returncode":None,"crash":False,"text":""}

def mutate(r,s,cap=12000):
    for _ in range(r.randint(1,10)):
        op=r.randrange(8)
        if op==0 and s:
            p=r.randrange(len(s)); s=s[:p]+chr(r.randrange(32,256))+s[p+1:]
        elif op==1:
            p=r.randrange(len(s)+1); ins=''.join(chr(r.choice([0,9,10,13,34,39,37,60,62,92,127,128,255,8238])) for _ in range(r.randint(1,40))); s=(s[:p]+ins+s[p:])[:cap]
        elif op==2 and s:
            a=r.randrange(len(s)); b=r.randrange(a,min(len(s),a+160)+1); s=s[:a]+s[b:]
        elif op==3 and s:
            a=r.randrange(len(s)); b=min(len(s),a+r.randint(1,120)); s=(s+s[a:b]*r.randint(1,8))[:cap]
        elif op==4: s=s[::-1]
        elif op==5: s=(s+r.choice(["../","..\\","%2e%2e%2f","$(MSBuildToolsPath)","@()","*?[]",";;&","--","/p:X=Y"]))[:cap]
        elif op==6: s=s.replace("/","\\") if r.randrange(2) else s.replace("\\","/")
        else: s=(s+chr(r.randrange(32,0x10000)))[:cap]
    return s

def save(outdir,kind,i,payload,result,cmd):
    d=outdir/f"{kind}-{i:05d}"; d.mkdir(parents=True,exist_ok=True)
    (d/"input.txt").write_text(payload,encoding="utf-8",errors="surrogatepass")
    (d/"result.json").write_text(json.dumps({"kind":kind,"index":i,"cmd":cmd,"result":result},indent=2),encoding="utf-8")

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--dotnet",required=True); ap.add_argument("--source",required=True); ap.add_argument("--out",required=True); ap.add_argument("--seed",type=int,default=8801); a=ap.parse_args()
    dotnet=str(Path(a.dotnet).resolve()); source=Path(a.source); out=Path(a.out); out.mkdir(parents=True,exist_ok=True); rng=random.Random(a.seed)
    sha=subprocess.check_output(["git","-C",str(source),"rev-parse","HEAD"],text=True).strip()
    (out/"source-sha.txt").write_text(sha+"\n"); (out/"dotnet-path.txt").write_text(dotnet+"\n")
    candidates=0; total=0
    work=Path(tempfile.mkdtemp(prefix="sdk-source-fuzz-"))
    project_seeds=[
      '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework></PropertyGroup></Project>',
      '<Project><PropertyGroup><A>$(A)</A><B>$([System.String]::Copy(\'x\'))</B></PropertyGroup></Project>',
      '<Project><ItemGroup><Compile Include="**/*.cs" Exclude="../**/*" /></ItemGroup></Project>',
      '<Project><Import Project="$(MSBuildToolsPath)\\Microsoft.Common.props" /></Project>',
      '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFrameworks>net10.0;net9.0</TargetFrameworks><RuntimeIdentifier>win-x64</RuntimeIdentifier></PropertyGroup></Project>'
    ]
    for i in range(350):
        total+=1; payload=mutate(rng,rng.choice(project_seeds)); proj=work/"fuzz.csproj"; pp=work/"pp.xml"; proj.write_text(payload,encoding="utf-8",errors="surrogatepass")
        if pp.exists(): pp.unlink()
        cmd=[dotnet,"msbuild",str(proj),"/nologo","/v:q",f"/pp:{pp}"]; res=run(cmd,work,8)
        if res["timeout"] or res["crash"] or (res["returncode"] is not None and res["returncode"]<0): candidates+=1; save(out,"msbuild",i,payload,res,cmd)
    template_seeds=[
      '{"author":"f","identity":"Fuzz.Source","name":"Fuzz","shortName":"fzsrc","sourceName":"SOURCE"}',
      '{"identity":"Fuzz.Source","name":"Fuzz","shortName":"fzsrc","symbols":{"p":{"type":"parameter","datatype":"string","defaultValue":"x"}}}',
      '{"identity":"Fuzz.Source","name":"Fuzz","shortName":"fzsrc","sources":[{"modifiers":[{"exclude":["**/bin/**","../**"]}]}]}'
    ]
    home=work/"home"; env=os.environ.copy(); env["DOTNET_CLI_HOME"]=str(home); env["DOTNET_NOLOGO"]="1"; env["DOTNET_CLI_TELEMETRY_OPTOUT"]="1"
    for i in range(120):
        total+=1; t=work/"template"; shutil.rmtree(t,ignore_errors=True); (t/".template.config").mkdir(parents=True); payload=mutate(rng,rng.choice(template_seeds))
        (t/".template.config"/"template.json").write_text(payload,encoding="utf-8",errors="surrogatepass"); (t/"SOURCE.txt").write_text("SOURCE",encoding="utf-8")
        cmd=[dotnet,"new","install",str(t),"--force"]; res=run(cmd,work,10,env)
        if res["timeout"] or res["crash"] or (res["returncode"] is not None and res["returncode"]<0): candidates+=1; save(out,"template",i,payload,res,cmd)
        run([dotnet,"new","uninstall",str(t)],work,5,env)
    arg_seeds=[["--info"],["--version"],["new","list"],["workload","list"],["msbuild","-version"],["build","--help"],["publish","--help"],["run","--help"]]
    for i in range(300):
        total+=1; args=list(rng.choice(arg_seeds))
        for _ in range(rng.randint(1,4)): args.insert(rng.randrange(len(args)+1),rng.choice(["","--","-","/","@missing.rsp","--property:X=Y","../x","%00","\ud800","--verbosity:diag"]))
        cmd=[dotnet]+args; res=run(cmd,work,8,env)
        if res["timeout"] or res["crash"] or (res["returncode"] is not None and res["returncode"]<0): candidates+=1; save(out,"cli",i," ".join(args),res,cmd)
    (out/"summary.txt").write_text(f"source_sha={sha}\ntotal_cases={total}\ncandidates={candidates}\nseed={a.seed}\n")
    print(f"DONE total={total} candidates={candidates}")
if __name__=="__main__": main()
