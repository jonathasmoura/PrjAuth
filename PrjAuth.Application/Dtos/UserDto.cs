namespace PrjAuth.Application.Dtos
{
	public class UserDto
	{
		public Guid Id { get; set; }
		public string Username { get; set; } = string.Empty;
		public string Email { get; set; } = string.Empty;
		public string[] Roles { get; set; } = Array.Empty<string>();
	}
}