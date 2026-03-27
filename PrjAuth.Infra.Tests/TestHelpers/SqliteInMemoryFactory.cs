using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using PrjAuth.Infra.DataContexts;

public static class SqliteInMemoryFactory
{
    public static DbContextOptions<DbAuthContext> CreateOptions(SqliteConnection connection)
    {
        // connection deve estar aberto pelo chamador e fechado ao final do teste
        var options = new DbContextOptionsBuilder<DbAuthContext>()
            .UseSqlite(connection)
            .Options;

        using var ctx = new DbAuthContext(options);
        ctx.Database.EnsureCreated();

        return options;
    }

    public static SqliteConnection CreateOpenConnection()
    {
        var connection = new SqliteConnection("DataSource=:memory:");
        connection.Open();
        return connection;
    }
}