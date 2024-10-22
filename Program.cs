using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using poplensUserAuthenticationApi.Contracts;
using poplensUserAuthenticationApi.Data;
using poplensUserAuthenticationApi.Models;
using poplensUserAuthenticationApi.Services;
using System.Text;
using DotNetEnv;

var builder = WebApplication.CreateBuilder(args);

DotNetEnv.Env.Load();

string connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING");

// Add services to the container.
// Configure database context with PostgreSQL
builder.Services.AddDbContext<UserDbContext>(options =>
    options.UseNpgsql(connectionString ?? builder.Configuration.GetConnectionString("DefaultConnection")));


builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddEnvironmentVariables();  // Load environment variables after appsettings.json



// Set up Identity with custom user and role
builder.Services.AddIdentity<User, IdentityRole>()
    .AddEntityFrameworkStores<UserDbContext>()
    .AddDefaultTokenProviders();


string jwtKey = Environment.GetEnvironmentVariable("JWT_KEY");
string issuer = Environment.GetEnvironmentVariable("JWT_ISSUER");
string audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE");
// Configure JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options => {
        options.TokenValidationParameters = new TokenValidationParameters {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer!,
            ValidAudience = audience!,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!))
        };
    });

// Add services for controllers and Swagger (for API documentation)
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => {
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "PopLens API", Version = "v1" });
});

// Add your AuthService and any other services
builder.Services.AddScoped<IUserAuthenticationService, UserAuthenticationService>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "PopLens API v1"));
}

app.UseHttpsRedirection();

app.UseAuthentication(); // Ensure this is before UseAuthorization
app.UseAuthorization();

app.MapControllers(); // Map controllers for routing

app.Run();
