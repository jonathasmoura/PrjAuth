using PrjAuth.Domain.Entities.DomainBase;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace PrjAuth.Domain.Entities
{
	public class User : EntityBase
	{
		private readonly List<string> _roles = new();
		public string Name { get; set; } = null!;
		public string? LastName { get; set; }
		public string Email { get; set; } = null!;
		public string PasswordHash { get; set; } = null!;
		public string? PasswordSalt { get; set; }
		public bool IsAdmin { get; set; }
		public IReadOnlyCollection<string> Roles => _roles.AsReadOnly();

		public string RolesJson
		{
			get => JsonSerializer.Serialize(_roles);
			set
			{
				_roles.Clear();
				if (string.IsNullOrWhiteSpace(value)) return;
				try
				{
					var items = JsonSerializer.Deserialize<List<string>>(value) ?? new List<string>();
					foreach (var r in items.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct())
					{
						_roles.Add(r);
					}
				}
				catch{}
			}
		}

		public User() { }

		public User(string name, string? lastName, string email, string passwordHash, bool isAdmin, IEnumerable<string>? roles = null)
		{
			Name = name;
			LastName = lastName;
			Email = email;
			PasswordHash = passwordHash;
			IsAdmin = isAdmin;

			if (roles != null)
			{
				foreach (var r in roles.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct())
				{
					_roles.Add(r);
				}
			}
		}
	}
}
