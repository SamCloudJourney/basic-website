using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;

const string SyncSwitch = "Microsoft.AspNetCore.DataProtection.KeyManagement.DisableAsyncKeyRingUpdate";
bool syncGuard = args.Contains("--sync", StringComparer.Ordinal);

AppContext.SetSwitch(SyncSwitch, syncGuard);

Console.WriteLine($"MODE={(syncGuard ? "SYNC_GUARD" : "DEFAULT_ASYNC")}");
Console.WriteLine($"FRAMEWORK={System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}");
Console.WriteLine($"OS={Environment.OSVersion}");

var repository = new BlockingXmlRepository();

var services = new ServiceCollection();
services.AddLogging();

services
    .AddDataProtection()
    .SetApplicationName("MSRC-DataProtection-Revocation-Race")
    .AddKeyManagementOptions(options =>
    {
        options.XmlRepository = repository;
    });

using ServiceProvider provider = services.BuildServiceProvider();

var dataProtectionProvider = provider.GetRequiredService<IDataProtectionProvider>();
var protector = dataProtectionProvider.CreateProtector("revocation-race-poc");
var keyManager = provider.GetRequiredService<IKeyManager>();

const string plaintext = "ADMIN_AUTH_COOKIE_SENTINEL_7a31";

// Force initial key generation and warm the in-memory KeyRingProvider cache.
string protectedPayload = protector.Protect(plaintext);
string baseline = protector.Unprotect(protectedPayload);

if (baseline != plaintext)
{
    throw new Exception("Baseline round trip failed.");
}

var initialKeys = keyManager.GetAllKeys();
if (initialKeys.Count != 1)
{
    throw new Exception($"Expected exactly one initial key, got {initialKeys.Count}.");
}

Guid keyId = initialKeys.Single().KeyId;

Console.WriteLine($"BASELINE_UNPROTECT=SUCCESS KEY={keyId}");
Console.WriteLine($"REPOSITORY_ELEMENTS_BEFORE_REVOKE={repository.Count}");

// The revocation operation persists a revocation record and then invalidates
// XmlKeyManager's cache-expiration token. Arm the repository so the *next*
// key-ring reload enters GetAllElements() and remains blocked.
repository.BlockNextRead();

keyManager.RevokeKey(keyId, "MSRC deterministic revocation race proof");

Console.WriteLine($"REVOKE_RETURNED=True KEY={keyId}");
Console.WriteLine($"REVOCATION_PERSISTED={repository.HasRevocationElement}");
Console.WriteLine($"REPOSITORY_ELEMENTS_AFTER_REVOKE={repository.Count}");

if (!repository.HasRevocationElement)
{
    throw new Exception("Revocation record was not persisted.");
}

// Start the first public IDataProtector.Unprotect call after RevokeKey.
// Product documentation says revocation invalidates the in-memory cache and
// the next Protect/Unprotect should reread the key ring.
var firstAfterRevoke = Task.Run(() =>
{
    try
    {
        string value = protector.Unprotect(protectedPayload);
        return new AttemptResult(true, value, null);
    }
    catch (Exception ex)
    {
        return new AttemptResult(false, null, ex);
    }
});

if (!repository.RefreshReadEntered.Wait(TimeSpan.FromSeconds(10)))
{
    repository.ReleaseBlockedRead();
    throw new Exception("The post-revocation key-ring reread did not enter the controlled repository.");
}

Console.WriteLine("POST_REVOKE_REFRESH_READ=ENTERED_AND_BLOCKED");

// Observe whether Unprotect returns while the authoritative post-revocation
// key-ring read is still blocked.
Task firstWinner = await Task.WhenAny(firstAfterRevoke, Task.Delay(TimeSpan.FromSeconds(3)));
bool completedBeforeRefresh = ReferenceEquals(firstWinner, firstAfterRevoke);

Console.WriteLine($"UNPROTECT_COMPLETED_WHILE_REFRESH_BLOCKED={completedBeforeRefresh}");

if (!syncGuard)
{
    // Default .NET 10 behavior under test: non-forced callers may return the stale
    // ring while an async refresh is in flight.
    if (!completedBeforeRefresh)
    {
        repository.ReleaseBlockedRead();
        throw new Exception("Default async path did not complete while refresh was blocked.");
    }

    AttemptResult result = await firstAfterRevoke;

    Console.WriteLine($"POST_REVOKE_STALE_UNPROTECT_SUCCESS={result.Success}");
    Console.WriteLine($"POST_REVOKE_STALE_PLAINTEXT={result.Value ?? "<none>"}");
    Console.WriteLine($"POST_REVOKE_STALE_EXCEPTION={result.Exception?.GetType().FullName ?? "<none>"}");

    if (!result.Success || result.Value != plaintext)
    {
        repository.ReleaseBlockedRead();
        throw new Exception("Expected stale-ring unprotect to reproduce before refresh completed.", result.Exception);
    }

    Console.WriteLine("REVOCATION_BYPASS_WINDOW=CONFIRMED");

    // Let the authoritative reread complete.
    repository.ReleaseBlockedRead();

    // Give the scheduled refresh a moment to finish; the next GetCurrentKeyRing()
    // consumes the completed task result.
    await Task.Delay(300);

    bool rejectedAfterRefresh = false;
    Exception? afterRefreshException = null;
    try
    {
        _ = protector.Unprotect(protectedPayload);
    }
    catch (Exception ex)
    {
        rejectedAfterRefresh = true;
        afterRefreshException = ex;
    }

    Console.WriteLine($"AFTER_REFRESH_UNPROTECT_REJECTED={rejectedAfterRefresh}");
    Console.WriteLine($"AFTER_REFRESH_EXCEPTION={afterRefreshException?.GetType().FullName ?? "<none>"}");

    if (!rejectedAfterRefresh)
    {
        throw new Exception("Payload remained valid even after refreshed ring observed revocation.");
    }

    Console.WriteLine("DEFAULT_ASYNC_REVOCATION_RACE=PASS");
}
else
{
    // Causal negative control. With async key-ring updates disabled, the old
    // synchronous path should block on the authoritative key-ring reread rather
    // than return the stale ring.
    if (completedBeforeRefresh)
    {
        AttemptResult early = await firstAfterRevoke;
        repository.ReleaseBlockedRead();
        throw new Exception(
            $"Synchronous guard unexpectedly completed before refresh. Success={early.Success}, Exception={early.Exception?.GetType().Name}");
    }

    Console.WriteLine("SYNC_GUARD_BLOCKED_UNTIL_AUTHORITATIVE_REFRESH=True");

    repository.ReleaseBlockedRead();

    AttemptResult result = await firstAfterRevoke.WaitAsync(TimeSpan.FromSeconds(10));

    Console.WriteLine($"SYNC_GUARD_POST_REFRESH_SUCCESS={result.Success}");
    Console.WriteLine($"SYNC_GUARD_POST_REFRESH_EXCEPTION={result.Exception?.GetType().FullName ?? "<none>"}");

    if (result.Success)
    {
        throw new Exception("Synchronous guard accepted payload protected by revoked key.");
    }

    Console.WriteLine("SYNC_GUARD_REVOKED_PAYLOAD_REJECTED=True");
    Console.WriteLine("SYNC_CAUSAL_CONTROL=PASS");
}

sealed record AttemptResult(bool Success, string? Value, Exception? Exception);

sealed class BlockingXmlRepository : IXmlRepository
{
    private readonly object _lock = new();
    private readonly List<XElement> _elements = new();
    private int _blockNextRead;

    public ManualResetEventSlim RefreshReadEntered { get; } = new(false);
    private ManualResetEventSlim ReleaseRefreshRead { get; } = new(false);

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _elements.Count;
            }
        }
    }

    public bool HasRevocationElement
    {
        get
        {
            lock (_lock)
            {
                return _elements.Any(e => string.Equals(e.Name.LocalName, "revocation", StringComparison.OrdinalIgnoreCase));
            }
        }
    }

    public void BlockNextRead()
    {
        RefreshReadEntered.Reset();
        ReleaseRefreshRead.Dispose();
        ReleaseRefreshRead = new ManualResetEventSlim(false);
        Interlocked.Exchange(ref _blockNextRead, 1);
    }

    public void ReleaseBlockedRead()
    {
        ReleaseRefreshRead.Set();
    }

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        if (Interlocked.Exchange(ref _blockNextRead, 0) == 1)
        {
            Console.WriteLine("REPOSITORY_GET_ALL_ELEMENTS=BLOCKING_REFRESH");
            RefreshReadEntered.Set();

            if (!ReleaseRefreshRead.Wait(TimeSpan.FromSeconds(20)))
            {
                throw new TimeoutException("Controlled repository refresh was not released.");
            }

            Console.WriteLine("REPOSITORY_GET_ALL_ELEMENTS=REFRESH_RELEASED");
        }

        lock (_lock)
        {
            return _elements.Select(e => new XElement(e)).ToArray();
        }
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        XElement clone = new(element);
        lock (_lock)
        {
            _elements.Add(clone);
        }

        Console.WriteLine($"REPOSITORY_STORE NAME={friendlyName} ELEMENT={clone.Name.LocalName}");
    }
}
