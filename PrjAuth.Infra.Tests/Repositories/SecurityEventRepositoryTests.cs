using PrjAuth.Infra.DataContexts;
using PrjAuth.Infra.Repositories;
using PrjAuth.Domain.Entities;

namespace PrjAuth.Infra.Tests.Repositories
{
    public class SecurityEventRepositoryTests
    {
        [Fact]
        public async Task AddAsync_Persists_SecurityEvent()
        {
            using var conn = SqliteInMemoryFactory.CreateOpenConnection();
            var options = SqliteInMemoryFactory.CreateOptions(conn);

            var evtId = Guid.NewGuid();
            await using (var ctx = new DbAuthContext(options))
            {
                var repo = new SecurityEventRepository(ctx);
                await repo.AddAsync(new SecurityEvent { Id = evtId, EventType = "TEST", Details = "desc" });
                await ctx.SaveChangesAsync();
            }

            await using (var ctx = new DbAuthContext(options))
            {
                var found = await ctx.SecurityEvents.FindAsync(evtId);
                Assert.NotNull(found);
                Assert.Equal("desc", found.Details);
                Assert.Equal("TEST", found.EventType);
            }

            conn.Close();
        }
    }
}
