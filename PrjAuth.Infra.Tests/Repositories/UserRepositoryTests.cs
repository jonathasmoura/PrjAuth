using PrjAuth.Infra.DataContexts;
using PrjAuth.Infra.Repositories;
using PrjAuth.Domain.Entities;

namespace PrjAuth.Infra.Tests.Repositories
{
    public class UserRepositoryTests
    {
        [Fact]
        public async Task Add_And_GetByEmail_Work()
        {
            using var conn = SqliteInMemoryFactory.CreateOpenConnection();
            var options = SqliteInMemoryFactory.CreateOptions(conn);

            await using (var context = new DbAuthContext(options))
            {
                var repo = new UserRepository(context);
                var user = new User
                {
                    Id = Guid.NewGuid(),
                    Email = "test@local",
                    Name = "T",
                    PasswordHash = "dummy-hash"
                };
                await repo.AddAsync(user);
                await context.SaveChangesAsync();
            }

            await using (var context = new DbAuthContext(options))
            {
                var repo = new UserRepository(context);
                var got = await repo.GetByEmailAsync("test@local");
                Assert.NotNull(got);
                Assert.Equal("test@local", got.Email);
            }

            conn.Close();
        }

        [Fact]
        public async Task Generic_CRUD_via_UserRepository()
        {
            using var conn = SqliteInMemoryFactory.CreateOpenConnection();
            var options = SqliteInMemoryFactory.CreateOptions(conn);

            Guid id;
            await using (var context = new DbAuthContext(options))
            {
                var repo = new UserRepository(context);
                var user = new User
                {
                    Id = Guid.NewGuid(),
                    Email = "a@b",
                    Name = "Name",
                    PasswordHash = "dummy-hash"
                };
                id = user.Id;
                await repo.AddAsync(user);
                await context.SaveChangesAsync();

                var fetched = await repo.GetByIdAsync(id);
                Assert.NotNull(fetched);

                fetched!.Name = "Updated";
                await repo.UpdateAsync(fetched);
                await context.SaveChangesAsync();
            }

            await using (var context = new DbAuthContext(options))
            {
                var repo = new UserRepository(context);
                var fetched = await repo.GetByIdAsync(id);
                Assert.Equal("Updated", fetched!.Name);

                await repo.DeleteAsync(fetched);
                await context.SaveChangesAsync();
            }

            await using (var context = new DbAuthContext(options))
            {
                var repo = new UserRepository(context);
                var fetched = await repo.GetByIdAsync(id);
                Assert.Null(fetched);
            }

            conn.Close();
        }
    }
}
