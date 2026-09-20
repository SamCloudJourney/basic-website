# Proposed remediation hypothesis

Research hypothesis only.

For a hard-link entry in PreserveLink mode, validation should account for the type and semantics of the object being
hard-linked, not only the resolved source pathname.

If `linkTargetPath` is a symbolic link on a platform where `File.CreateHardLink` preserves the symlink inode, obtain
the symlink's raw `LinkTarget` and evaluate that target as it would resolve from the hard-link destination.

Conceptually:

```csharp
FileInfo source = new(linkTargetPath);

if (source.LinkTarget is string rawSymlinkTarget)
{
    string rebased = Path.IsPathFullyQualified(rawSymlinkTarget)
        ? rawSymlinkTarget
        : Path.Join(Path.GetDirectoryName(fileDestinationPath), rawSymlinkTarget);

    string? rebasedDestination =
        GetFullDestinationPath(destinationDirectoryPath, rebased);

    if (rebasedDestination is null ||
        FilePathEscapesDirectory(destinationDirectoryPath, rebasedDestination))
    {
        throw new IOException(...);
    }
}
```

The exact product fix may instead choose to reject hard-link entries whose source is a symlink, or deliberately
dereference/copy the resolved source. The invariant is:

> A link created by archive extraction must not resolve outside the extraction root after creation, regardless of
> whether it was introduced directly as a symbolic-link entry or indirectly by hard-linking a symbolic link.

Regression coverage should include:

1. direct outside symlink rejected;
2. safe deep relative symlink + hardlink to same-depth equivalent remains contained;
3. safe deep relative symlink + shallower hardlink that rebases outside is rejected;
4. deeper/multi-level relative target variant;
5. dangling rebased symlink variant;
6. sync and async extraction;
7. default `TarHardLinkMode.PreserveLink`;
8. Linux behavior specifically;
9. macOS behavior retained or made consistent by explicit product policy.
