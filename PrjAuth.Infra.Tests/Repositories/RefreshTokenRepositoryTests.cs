using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;
using PrjAuth.Infra.DataContexts;
using PrjAuth.Infra.Repositories;
using PrjAuth.Domain.Entities;

namespace PrjAuth.Infra.Tests.Repositories
{
    public class RefreshTokenRepositoryTests
    {
        private static string ComputeSha256Hash(string raw)
        {
            using var sha = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(raw);
            var hash = sha.ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        [Fact]
        public async Task GetByTokenAsync_Finds_By_RawToken()
        {
            using var conn = SqliteInMemoryFactory.CreateOpenConnection();
            var options = SqliteInMemoryFactory.CreateOptions(conn);

            var raw = "plain-token";
            var hashed = ComputeSha256Hash(raw);
            var userId = Guid.NewGuid();

            await using (var ctx = new DbAuthContext(options))
            {
                ctx.RefreshTokens.Add(new RefreshToken { Id = new int(), Token = hashed, UserId = userId });
                await ctx.SaveChangesAsync();
            }

            await using (var ctx = new DbAuthContext(options))
            {
                var repo = new RefreshTokenRepository(ctx);
                var found = await repo.GetByTokenAsync(raw);
                Assert.NotNull(found);
                Assert.Equal(userId, found.UserId);
            }

            conn.Close();
        }

        [Fact]
        public async Task RevokeAllUserTokensAsync_Marks_Tokens_As_Revoked()
        {
            using var conn = SqliteInMemoryFactory.CreateOpenConnection();
            var options = SqliteInMemoryFactory.CreateOptions(conn);

            var userId = Guid.NewGuid();
            await using (var ctx = new DbAuthContext(options))
            {
                ctx.RefreshTokens.AddRange(
                    new RefreshToken { Id = new int() , Token = "t1", UserId = userId, Revoked = false },
                    new RefreshToken { Id = new int(), Token = "t2", UserId = userId, Revoked = false }
                );
                await ctx.SaveChangesAsync();
            }

            await using (var ctx = new DbAuthContext(options))
            {
                var repo = new RefreshTokenRepository(ctx);
                await repo.RevokeAllUserTokensAsync(userId, "1.2.3.4");
                await ctx.SaveChangesAsync(); // as repo only calls UpdateRange
            }

            await using (var ctx = new DbAuthContext(options))
            {
                var tokens = ctx.RefreshTokens.Where(r => r.UserId == userId).ToList();
                Assert.All(tokens, t => Assert.True(t.Revoked));
                Assert.All(tokens, t => Assert.NotNull(t.RevokedAt));
                Assert.All(tokens, t => Assert.Equal("1.2.3.4", t.RevokedByIp));
            }

            conn.Close();
        }
    }
}
