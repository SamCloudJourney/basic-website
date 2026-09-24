import argparse, json, os, random, struct, subprocess, tempfile
from pathlib import Path

MARKERS = (
    "Unhandled exception", "Stack overflow", "Fatal error", "AccessViolationException",
    "FatalExecutionEngineError", "System.NullReferenceException", "System.IndexOutOfRangeException",
    "System.ArgumentOutOfRangeException", "System.OutOfMemoryException"
)

def run(cmd, cwd, timeout):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace", timeout=timeout)
        text = (p.stdout or "") + "\n" + (p.stderr or "")
        return {
            "timeout": False,
            "returncode": p.returncode,
            "marker": next((m for m in MARKERS if m.lower() in text.lower()), None),
            "text": text[-30000:],
        }
    except subprocess.TimeoutExpired:
        return {"timeout": True, "returncode": None, "marker": None, "text": ""}

def locate_ref_dir(source: Path) -> Path:
    root = source / ".dotnet" / "packs" / "Microsoft.NETCore.App.Ref"
    candidates = []
    for version in root.iterdir():
        ref = version / "ref"
        if not ref.is_dir():
            continue
        for tfm in ref.iterdir():
            if tfm.is_dir() and tfm.name.startswith("net"):
                candidates.append((version.name, tfm.name, tfm))
    if not candidates:
        raise RuntimeError("No Microsoft.NETCore.App.Ref reference directory found")
    candidates.sort()
    return candidates[-1][2]

def interesting_positions(data: bytes):
    pos = {0, 1, 2, 0x3c}
    if len(data) >= 0x40:
        pe = struct.unpack_from("<I", data, 0x3c)[0]
        if 0 <= pe <= len(data) - 24 and data[pe:pe+4] == b"PE\0\0":
            pos.update([pe, pe+1, pe+2, pe+4, pe+6, pe+20, pe+22])
            opt = pe + 24
            if opt + 2 <= len(data):
                magic = struct.unpack_from("<H", data, opt)[0]
                dd = opt + (96 if magic == 0x10B else 112 if magic == 0x20B else 0)
                pos.update([opt, opt+2, opt+16, opt+20, opt+32, opt+36, opt+56, opt+60])
                if dd:
                    cli = dd + 14 * 8
                    pos.update(range(cli, min(cli + 8, len(data))))
            if pe + 22 <= len(data):
                sections = struct.unpack_from("<H", data, pe + 6)[0]
                opt_size = struct.unpack_from("<H", data, pe + 20)[0]
                sh = opt + opt_size
                for i in range(min(sections, 32)):
                    base = sh + 40 * i
                    if base + 40 > len(data):
                        break
                    pos.update([base+8, base+12, base+16, base+20, base+32, base+36])
    sig = data.find(b"BSJB")
    if sig >= 0:
        pos.update(range(max(0, sig - 16), min(len(data), sig + 96)))
    for marker in (b"#~", b"#-", b"#Strings", b"#Blob", b"#GUID", b"#US"):
        start = 0
        while True:
            q = data.find(marker, start)
            if q < 0:
                break
            pos.update(range(max(0, q - 12), min(len(data), q + len(marker) + 12)))
            start = q + 1
    return [p for p in sorted(pos) if 0 <= p < len(data)]

def mutate(rng: random.Random, seed: bytes, interesting):
    d = bytearray(seed)
    mode = rng.randrange(8)

    if mode == 0 and d:
        for _ in range(rng.randint(1, 8)):
            p = rng.choice(interesting) if interesting and rng.randrange(4) else rng.randrange(len(d))
            d[p] ^= 1 << rng.randrange(8)
    elif mode == 1 and d:
        p = rng.choice(interesting) if interesting else rng.randrange(len(d))
        width = rng.choice([1, 2, 4, 8])
        values = [0, 1, 0x7f, 0x80, 0xff, 0xffff, 0xffffffff, 0x7fffffff]
        v = rng.choice(values)
        for i in range(width):
            if p + i < len(d):
                d[p+i] = (v >> (8*i)) & 0xff
    elif mode == 2 and len(d) > 32:
        cut = rng.randrange(1, len(d))
        d = d[:cut]
    elif mode == 3 and d:
        p = rng.choice(interesting) if interesting else rng.randrange(len(d))
        n = min(rng.randint(1, 64), len(d) - p)
        if n > 0:
            d[p:p+n] = bytes([rng.choice([0, 0xff, 0x7f, 0x80])]) * n
    elif mode == 4 and len(d) < 2_000_000:
        p = rng.randrange(len(d) + 1)
        n = rng.randint(1, 128)
        d[p:p] = os.urandom(n)
    elif mode == 5 and len(d) > 64 and len(d) < 2_000_000:
        a = rng.randrange(len(d))
        n = min(rng.randint(1, 256), len(d) - a)
        p = rng.randrange(len(d) + 1)
        d[p:p] = d[a:a+n]
    elif mode == 6 and len(d) > 64:
        a = rng.randrange(len(d))
        n = min(rng.randint(1, 256), len(d) - a)
        del d[a:a+n]
    elif d:
        for _ in range(rng.randint(1, 16)):
            p = rng.randrange(len(d))
            d[p] = rng.randrange(256)

    return bytes(d[:2_000_000])

def save(outdir: Path, idx: int, payload: bytes, result, mode):
    d = outdir / f"candidate-{idx:05d}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "ref.dll").write_bytes(payload)
    (d / "result.json").write_text(json.dumps({"index": idx, "mode": mode, "result": result}, indent=2), encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--iterations", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=424242)
    args = ap.parse_args()

    source = Path(args.source).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)

    dotnet = source / ".dotnet" / "dotnet.exe"
    cscs = list((source / "artifacts" / "bin" / "csc" / "Release").glob("net*/csc.dll"))
    if not dotnet.exists() or not cscs:
        raise RuntimeError("repo-built dotnet/csc not found")
    csc = sorted(cscs)[-1]
    refdir = locate_ref_dir(source)
    refs = sorted(refdir.glob("*.dll"))

    work = Path(tempfile.mkdtemp(prefix="roslyn-pe-fuzz-"))
    seed_src = work / "seed.cs"
    seed_dll = work / "seed.dll"
    seed_rsp = work / "seed.rsp"
    seed_src.write_text(
        "public class SeedLib { public static int X = 7; public virtual string M(int x) => x.ToString(); public class Nested<T> { public T? V; } }",
        encoding="utf-8",
    )
    seed_rsp.write_text("\n".join([
        "/nologo", "/target:library", f"/out:{seed_dll}",
        *[f"/r:{p}" for p in refs],
        str(seed_src)
    ]), encoding="utf-8")
    seed_build = run([str(dotnet), str(csc), "@" + str(seed_rsp)], work, 30)
    if seed_build["returncode"] != 0 or not seed_dll.exists():
        (out / "seed-build.json").write_text(json.dumps(seed_build, indent=2), encoding="utf-8")
        raise RuntimeError("failed to build seed reference")

    probe = work / "probe.cs"
    probe.write_text("public static class Use { public static int M() => SeedLib.X; }", encoding="utf-8")
    base_rsp = work / "base.rsp"
    base_rsp.write_text("\n".join([
        "/nologo", "/target:library", f"/out:{work / 'probe.dll'}",
        *[f"/r:{p}" for p in refs],
        str(probe)
    ]), encoding="utf-8")

    seed_bytes = seed_dll.read_bytes()
    interesting = interesting_positions(seed_bytes)
    (out / "metadata.txt").write_text(
        f"source_sha={subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()}\n"
        f"csc={csc}\nrefdir={refdir}\nseed_size={len(seed_bytes)}\ninteresting_positions={len(interesting)}\n",
        encoding="utf-8",
    )

    candidates = 0
    for i in range(args.iterations):
        payload = mutate(rng, seed_bytes, interesting)
        mut = work / "mut.dll"
        mut.write_bytes(payload)
        mode = "targeted"
        result = run([str(dotnet), str(csc), "@" + str(base_rsp), f"/r:{mut}"], work, 6)
        is_candidate = result["timeout"] or result["marker"] is not None or result["returncode"] not in (0, 1)
        if is_candidate:
            candidates += 1
            save(out, candidates, payload, result, mode)
            if candidates >= 100:
                break

    (out / "summary.txt").write_text(
        f"iterations={args.iterations}\nseed={args.seed}\ncandidates={candidates}\nseed_size={len(seed_bytes)}\n",
        encoding="utf-8",
    )
    print(f"DONE iterations={args.iterations} candidates={candidates}")

if __name__ == "__main__":
    main()
