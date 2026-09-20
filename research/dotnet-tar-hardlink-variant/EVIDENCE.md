# System.Formats.Tar hard-link rebasing bypasses patched symlink containment on Linux

## Summary

Patched `TarFile.ExtractToDirectory` rejects a direct symbolic link whose target escapes the destination directory.
However, on Linux an archive can create a relative symbolic link that is safe at its original deep path and then create
a hard-link entry to that symlink at a shallower path.

`System.Formats.Tar` validates the hard-link source path as safe, then calls `File.CreateHardLink` using the original
source path. On Linux, `File.CreateHardLink` ultimately calls `Interop.Sys.Link`, which hard-links the symlink inode
rather than dereferencing it.

The symlink's relative target text is unchanged, but because the new hard link has a different parent directory, the
same relative target can now resolve outside the extraction root.

This leaves an attacker-created filesystem entry inside the extraction directory that resolves outside the directory,
despite the post-CVE containment checks.

## Clean validated run

GitHub Actions:

https://github.com/SamCloudJourney/basic-website/actions/runs/35527087710

Branch:

`research/dotnet-runtime-tar-hardlink-variant-20260920`

Validated serviced runtimes:

- .NET 8.0.31 / Ubuntu 24.04.5
- .NET 9.0.20 / Ubuntu 24.04.5
- .NET 10.0.12 / Ubuntu 24.04.5
- .NET 10.0.12 / macOS 15.7.9 negative control

## Direct patched control

Archive:

```text
escape -> ../outside
```

Patched runtime:

```text
DIRECT_OUTSIDE_SYMLINK_REJECTED=True
```

So the published containment fix is active.

## Bypass archive

Archive semantics:

```text
a/
inside                           regular file: SAFE_INSIDE
a/s -> ../inside                 symbolic link; safe at this location
escape hardlink -> a/s           hard link to the symlink
```

At `a/s`, target `../inside` resolves to:

```text
<destination>/inside
```

which is contained.

On Linux the hard-link entry creates another name for that symlink inode at:

```text
<destination>/escape
```

Its stored target is still:

```text
../inside
```

but from the new parent that resolves to:

```text
<parent-of-destination>/inside
```

which is outside the extraction root.

Confirmed output on .NET 8/9/10 Linux:

```text
SOURCE_LINK_TARGET=../inside
ESCAPE_LINK_TARGET=../inside
SOURCE_READ=SAFE_INSIDE
ESCAPE_READ=OUTSIDE_SENTINEL_61af

SOURCE_RESOLVED=<destination>/inside
ESCAPE_RESOLVED=<outside destination>

TAR_HARDLINK_REBASED_SYMLINK_ESCAPE=CONFIRMED
```

## Generality

A deeper independent construction also passed:

```text
d1/d2/d3/d4/s -> ../outside2/secret
escape2 hardlink -> d1/d2/d3/d4/s
```

At the source path the link resolves safely to a contained archive-created file.
After rebasing to `escape2`, the identical target resolves to a different researcher-controlled path outside the root.

Marker:

```text
TAR_HARDLINK_REBASE_GENERALITY=CONFIRMED
```

## Async parity

The same containment bypass occurs through `TarFile.ExtractToDirectoryAsync`:

```text
TAR_HARDLINK_REBASED_SYMLINK_ESCAPE_ASYNC=CONFIRMED
```

## Practical outside-write primitive

A third archive creates a contained dangling symlink and rebases it with a hard-link entry:

```text
x/y/s -> ../future-created.txt
escape-write hardlink -> x/y/s
```

At its original path, `../future-created.txt` is inside the extraction root.

After rebasing to the root-level `escape-write`, the target resolves outside the extraction root.

Extraction returns successfully. The outside target does not exist before the post-extraction write.

An ordinary caller operation against the supposedly-contained extracted path:

```csharp
File.WriteAllText(Path.Combine(destination, "escape-write"), "POST_EXTRACTION_OUTSIDE_WRITE_5ea2");
```

creates:

```text
<parent-of-destination>/future-created.txt
```

with the controlled marker.

Confirmed:

```text
TAR_REBASED_SYMLINK_OUTSIDE_WRITE_PRIMITIVE=CONFIRMED
```

Important scope note: the extractor itself does not perform this final write. The vulnerability is that extraction
successfully returns an attacker-controlled link that resolves outside the promised destination containment boundary.
Any subsequent consumer that opens/writes the extracted path can therefore cross that boundary.

## macOS negative control

macOS does not preserve the symlink inode in this `File.CreateHardLink` scenario. The hard-link destination is a
normal hard link to the resolved contained file:

```text
MACOS_HARDLINK_SYMLINK_DEREFERENCE_CONTROL=PASS
```

The demonstrated bypass is therefore Linux-specific.

## Root cause in current source

Validated source commit:

`12921b1d8c6865a774232de9379133020ad23d79`

`TarEntry.GetDestinationAndLinkPaths()` validates the hard-link target path:

```csharp
string? linkDestination = GetFullDestinationPath(
    destinationDirectoryPath,
    Path.Join(destinationDirectoryPath, linkName));

if (linkDestination is null ||
    FilePathEscapesDirectory(destinationDirectoryPath, linkDestination))
{
    throw new IOException(...);
}

linkTargetPath = linkDestination;
```

This asks whether the hard-link **source path**, when resolved at its original location, escapes.

Later the default `TarHardLinkMode.PreserveLink` path calls:

```csharp
File.CreateHardLink(hardLinkFilePath, targetFilePath);
```

On Unix, `File.CreateHardLink` reaches:

```csharp
Interop.Sys.Link(pathToTarget, path)
```

On Linux, if `pathToTarget` is a symlink, the symlink inode itself is hard-linked.

The missing security decision is:

> If the hard-link source is itself a symbolic link, will the symlink target remain inside the extraction root when
> interpreted from the hard-link destination path?

The current check answers only whether it is safe from the source location.

## Relation to CVE-2026-45491 fix

Fix commit:

`710da3b3104ff8e0415720d173b1b6c8a2f970dc`

The fix added `FilePathEscapesDirectory`, `ResolvePhysicalPath`, and symlink-aware checks specifically to prevent an
archive from escaping the extraction root through links introduced by earlier archive entries.

The direct malicious symlink control confirms those checks are active on the tested patched versions.

This variant reaches the same forbidden final filesystem state through a hard-link operation whose source link is safe
before rebasing.

## Public duplicate search

Exact public GitHub searches were performed for combinations of:

- System.Formats.Tar + hardlink + symlink
- rebased symlink
- CVE-2026-45491 + hardlink
- File.CreateHardLink + symlink

No public issue describing this hard-link rebasing containment bypass was found as of 2026-09-20.

All files, paths, sentinels, and outside targets in the reproduction are researcher-controlled temporary files.


## Multi-parent escape generality

Clean run:

https://github.com/SamCloudJourney/basic-website/actions/runs/35527839942

A third independent construction uses the raw symlink target:

```text
../../../outside3/secret
```

At the original archive path:

```text
p1/p2/p3/s -> ../../../outside3/secret
```

that resolves to a file still inside the extraction root.

The archive then creates:

```text
escape3 hardlink -> p1/p2/p3/s
```

On Linux, the new root-level hard link preserves the same symlink inode and therefore the same raw
`../../../outside3/secret` target. From the new location it traverses multiple parent levels outside
the extraction root.

Confirmed on .NET 8.0.31, 9.0.20 and 10.0.12:

```text
MULTIPARENT_LINK_TARGET=../../../outside3/secret
MULTIPARENT_ESCAPE_RESOLVED=<controlled path outside extraction root>
TAR_HARDLINK_MULTIPARENT_ESCAPE=CONFIRMED
```

This shows the primitive is not limited to a single `..` or immediate sibling of the destination.

## Intended boundary of the CVE-2026-45491 fix

The public review discussion for fix PR #129281 explicitly narrowed the patch's intended guarantee:
it is meant to defend against directory-escaping symlinks **introduced by the archive itself**, while
pre-existing symlinks already present in the destination are treated as caller-controlled state.

This variant is fully within that intended guarantee:

- the safe source symlink is created by an archive entry;
- the hard-link entry is created by the same archive;
- no pre-existing destination symlink is required;
- the escaping final link exists only because the archive caused .NET to rebase the symlink inode.

The review discussion contains no consideration of hard-linking a safe symbolic link into a new parent
directory and re-evaluating its relative target from that destination.
