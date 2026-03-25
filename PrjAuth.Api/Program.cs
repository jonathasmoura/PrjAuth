using Microsoft.EntityFrameworkCore;
using PrjAuth.Application.ServiceExtensions;
using PrjAuth.Infra.DataContexts;
using PrjAuth.Api.ServiceExtensions;
using PrjAuth.Infra.ServiceExtensions;
using PrjAuth.Api.Middlewares;
using PrjAuth.Application.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddLoadBalancedTokenConfiguration(builder.Configuration);

builder.Services.AddLoadBalancedJwtAuthentication(builder.Configuration);

builder.Services.AddSwaggerWithJwt();

builder.Services.AddControllers();

builder.Services.AddHealthChecks();

builder.Services.Configure<PrjAuth.Api.Config.RateLimitingOptions>(builder.Configuration.GetSection("RateLimiting"));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<DbAuthContext>();
        context.Database.Migrate();
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while migrating the database.");
    }
}

// Configure the HTTP request pipeline.
app.UseMiddleware<ExceptionHandlingMiddleware>();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthRateLimiting();

app.UseHttpsRedirection();
app.UseCors(opt => opt.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin());

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapHealthChecks("/health");

app.Run();
