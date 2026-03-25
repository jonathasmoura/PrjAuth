using Microsoft.EntityFrameworkCore;
using PrjAuth.Application.ServiceExtensions;
using PrjAuth.Infra.DataContexts;
using PrjAuth.Api.ServiceExtensions;
using PrjAuth.Infra.ServiceExtensions;
using PrjAuth.Api.Middlewares;
using PrjAuth.Application.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDIInfrastuctureServices(builder.Configuration)
                .AddDIApplicationServices(builder.Configuration);

// Adiciona configuração de autenticação JWT (Application)
builder.Services.AddLoadBalancedTokenConfiguration(builder.Configuration);

// configurar autenticação usando primary/secondary
builder.Services.AddLoadBalancedJwtAuthentication(builder.Configuration);

// Swagger (Api extension)
builder.Services.AddSwaggerWithJwt();

builder.Services.AddControllers();

// Health checks
builder.Services.AddHealthChecks();

// Registrar cache distribuído mínimo para desenvolvimento / testes.
builder.Services.AddDistributedMemoryCache(); // resolve IDistributedCache

// configurar opções
builder.Services.Configure<PrjAuth.Api.Config.RateLimitingOptions>(builder.Configuration.GetSection("RateLimiting"));

// garantir IDistributedCache (ex.: Redis) já configurado em produção
// builder.Services.AddStackExchangeRedisCache(...); // se for usar Redis

// ---------------------------------------------------------------
// Resolve e registra TokenSecrets de forma assíncrona no startup.
// Isso evita chamadas .GetAwaiter().GetResult() em construtores.
// ---------------------------------------------------------------
using (var tempProvider = builder.Services.BuildServiceProvider())
{
	// Resolve LoadBalancedTokenConfiguration já registrado
	var lbConfig = tempProvider.GetRequiredService<LoadBalancedTokenConfiguration>();
	// Buscar secrets de forma assíncrona
	var primary = await lbConfig.GetPrimarySecretAsync().ConfigureAwait(false);
	var secondary = await lbConfig.GetSecondarySecretAsync().ConfigureAwait(false);

	// Registrar TokenSecrets para injeção no TokenService
	builder.Services.AddSingleton(new TokenSecrets(primary ?? string.Empty, secondary ?? string.Empty));
}

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
