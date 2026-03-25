using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace PrjAuth.Application.Tests.TestHelpers;
public static class DistributedCacheFactory
{
    public static IDistributedCache CreateMemoryDistributedCache()
    {
        return new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
    }
}
