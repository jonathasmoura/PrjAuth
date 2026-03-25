using System;

namespace PrjAuth.Domain.Entities
{
	public class SecurityEvent
	{
		public Guid Id { get; set; } = Guid.NewGuid();
		public string EventType { get; set; } = string.Empty;
		public string Details { get; set; } = string.Empty;
		public string? UserId { get; set; }
		public DateTime Timestamp { get; set; } = DateTime.UtcNow;
		public string? IpAddress { get; set; }
		public string? UserAgent { get; set; }
	}
}
