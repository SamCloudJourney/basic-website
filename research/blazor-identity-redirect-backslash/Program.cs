string[] values =
{
    @"\\evil.example",
    @"/\evil.example",
    @"\/evil.example",
    @"\evil.example",
    @"//evil.example",
    @"///evil.example",
    @"%5C%5Cevil.example",
};

Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
foreach (string value in values)
{
    bool relative = Uri.IsWellFormedUriString(value, UriKind.Relative);
    bool literalDoubleSlash = value.StartsWith("//", StringComparison.Ordinal);
    bool currentGuardAccepts = relative && !literalDoubleSlash;
    Console.WriteLine($"DOTNET VALUE={Escape(value)} RELATIVE={relative} STARTS_DSLASH={literalDoubleSlash} GUARD_ACCEPTS={currentGuardAccepts}");
}

static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\r","\\r").Replace("\n","\\n");
