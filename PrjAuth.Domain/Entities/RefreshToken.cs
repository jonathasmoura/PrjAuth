using System;

namespace PrjAuth.Domain.Entities
{
	public class RefreshToken
	{
		public int Id { get; set; }
		public string Token { get; set; } = string.Empty;
		public Guid UserId { get; set; }
		public string Username { get; set; } = string.Empty;
		public DateTime CreatedAt { get; set; }
		public string CreatedByIp { get; set; } = string.Empty;
		public DateTime ExpiresAt { get; set; }
		public bool Revoked { get; set; }
		public DateTime? RevokedAt { get; set; }
		public string RevokedByIp { get; set; } = string.Empty;
		public string ReplacedByToken { get; set; } = string.Empty;
		public bool IsActive => !Revoked && DateTime.UtcNow <= ExpiresAt;
	}
}
