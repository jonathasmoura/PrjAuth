using Microsoft.EntityFrameworkCore;
using PrjAuth.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Infra.DataContexts
{	
	public class DbAuthContext : DbContext
	{
		public DbAuthContext(DbContextOptions<DbAuthContext> options)
			: base(options) { }
		public DbSet<User> Users { get; set; }
		public DbSet<RefreshToken> RefreshTokens { get; set; }
		public DbSet<SecurityEvent> SecurityEvents { get; set; }
		protected override void OnModelCreating(ModelBuilder modelBuilder)
		{
			base.OnModelCreating(modelBuilder);

		}
	}
}
