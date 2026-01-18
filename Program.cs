using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using StackExchange.Redis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using WebApi.DapperContext;
using WebApi.Filters;
using WebApi.Interface.Repositories.Log;
using WebApi.Interface.Services.LogServiceInterfaces;
using WebApi.Middlewares;
using WebApi.Services.LogServices;
using WebAPi.Repositories.Log;

var builder = WebApplication.CreateBuilder(args);

/* =========================================================
   🔐 REDIS CONNECTION (TOKEN REVOCATION, ANTI-REPLAY, REFRESH TOKEN HOOK)
   =========================================================
   - Redis is used to store active JWTs for revocation
   - Also helps anti-replay (same token spam detection)
   - Enables refresh token rotation later
*/
builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    var redisConnection = builder.Configuration.GetConnectionString("Redis");
    if (string.IsNullOrEmpty(redisConnection))
        throw new Exception("Redis connection string missing");

    return ConnectionMultiplexer.Connect(redisConnection);
});

/* =========================================================
   🔐 CONTROLLERS HARDENING
   =========================================================
   - Reject invalid content-types
   - JSON-only API (prevent XXE attacks)
*/



builder.Services.AddControllers(options =>
{
    
    options.ReturnHttpNotAcceptable = true; // Reject unsupported media types
    // Remove XML formatters for security
    options.InputFormatters.RemoveType<Microsoft.AspNetCore.Mvc.Formatters.XmlSerializerInputFormatter>();
    options.OutputFormatters.RemoveType<Microsoft.AspNetCore.Mvc.Formatters.XmlSerializerOutputFormatter>();

    // Validate models
    options.Filters.Add<ValidateModelFilter>();
})
.AddJsonOptions(opt =>
{
    opt.JsonSerializerOptions.PropertyNamingPolicy = null; // Keep original property names
    opt.JsonSerializerOptions.WriteIndented = false;       // Minified JSON
});

/* API behavior config */
builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.SuppressModelStateInvalidFilter = false; // Default validation
});

/* API explorer for Swagger */
builder.Services.AddEndpointsApiExplorer();

/* =========================================================
   🚦 RATE LIMITING (PER USER / PER IP)
   =========================================================
   - Brute force protection
   - Prevent abuse of APIs
*/
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("user-limit", context =>
    {
        var userId =
            context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value
            ?? context.Connection.RemoteIpAddress?.ToString()
            ?? "anonymous";

        return RateLimitPartition.GetFixedWindowLimiter(
            userId,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,       // Max 10 requests per window
                Window = TimeSpan.FromSeconds(10)
            });
    });
});

/* =========================================================
   📄 SWAGGER CONFIGURATION (DEV ONLY)
   =========================================================
   - JWT secured Swagger
   - Only shows in Development
*/
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "RechargeB2B Secure APIs",
        Version = "v1"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

/* =========================================================
   🔑 JWT AUTHENTICATION (BANK-LEVEL)
   =========================================================
   - Enforce HTTPS
   - Validate issuer/audience
   - Redis-based token revocation
   - Anti-replay token detection
*/

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = true;  // Only accept HTTPS
    options.SaveToken = false;            // Do not save token in memory

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = TimeSpan.Zero,  // No grace period for expiry

        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]!)
        )
    };

    options.Events = new JwtBearerEvents
    {
        // Reject HTTP tokens
        OnMessageReceived = context =>
        {
            if (!context.Request.IsHttps)
                context.NoResult();
            return Task.CompletedTask;
        },

        // Token revocation & anti-replay
        OnTokenValidated = async context =>
        {
            var jti = context.Principal?
                .FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

            if (string.IsNullOrEmpty(jti))
            {
                context.Fail("Missing jti");
                return;
            }

            var redis = context.HttpContext
                .RequestServices
                .GetRequiredService<IConnectionMultiplexer>();

            var db = redis.GetDatabase();

            // Token revoked / logout
            if (!await db.KeyExistsAsync($"jwt:{jti}"))
            {
                context.Fail("Token revoked");
                return;
            }

            // Anti-replay: prevent same token used multiple times
            var replayKey = $"replay:{jti}";
            if (!await db.StringSetAsync(
                    replayKey,
                    "1",
                    TimeSpan.FromSeconds(30),
                    When.NotExists))
            {
                context.Fail("Replay attack detected");
            }
        }
    };
});
builder.Services.AddSingleton<ILoggingRepository, LoggingRepository>();
builder.Services.AddSingleton<IDapperContext, DapperContext>();
builder.Services.AddSingleton<ILoggingService, LoggingService>();
/* =========================================================
   🔒 AUTHORIZATION (ZERO TRUST)
   =========================================================
   - All APIs require authentication by default
   - Role-based policies
*/
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();

    options.AddPolicy("AdminOnly",
        policy => policy.RequireRole("Admin"));

    options.AddPolicy("CanRecharge", policy =>
        policy.RequireAssertion(context =>
        {
            var role = context.User.FindFirst(ClaimTypes.Role)?.Value;
            return role == "Agent" || role == "Distributor";
        }));
});

/* =========================================================
   🌐 CORS CONFIGURATION
   =========================================================
   - Restrict origins and methods
*/
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
        policy.WithOrigins("https://yourclientdomain.com")
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .WithHeaders("Content-Type", "Authorization");
    });
});

/* =========================================================
   ⏱ REQUEST TIMEOUT (ANTI-HANG)
   ========================================================= */
builder.Services.AddRequestTimeouts(options =>
{
    options.DefaultPolicy = new Microsoft.AspNetCore.Http.Timeouts.RequestTimeoutPolicy
    {
        Timeout = TimeSpan.FromSeconds(10)
    };
});

/* =========================================================
   📦 REQUEST SIZE LIMIT + TLS CONFIG
   ========================================================= */
builder.WebHost.ConfigureKestrel(options =>
{
    // TLS strict (TLS12 + TLS13 only)
    options.ConfigureHttpsDefaults(https =>
    {
        https.SslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                             System.Security.Authentication.SslProtocols.Tls13;
    });

    // Max request body size 1 MB
    options.Limits.MaxRequestBodySize = 1_000_000;
});

if (builder.Environment.IsDevelopment())
{
    builder.Logging.AddConsole();
    builder.Logging.AddDebug();
}
var app = builder.Build();

/* =========================================================
   🚨 GLOBAL EXCEPTION HANDLER
   =========================================================
   - Do not leak stack trace
   - Return generic error message
*/
//app.UseExceptionHandler(appErr =>
//{
//    appErr.Run(async context =>
//    {
//        context.Response.StatusCode = 500;
//        context.Response.ContentType = "application/json";
//        await context.Response.WriteAsync(
//            "{\"error\":\"Internal server error\"}");
//    });
//});

/* =========================================================
   📄 SWAGGER PIPELINE
   ========================================================= */


if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
            {
             c.SwaggerEndpoint("/swagger/v1/swagger.json", "Recharge B2B  APIs v1");
            });
        }
        else
        {
            // Disable Swagger in production
            app.MapGet("/swagger/{**any}", () => Results.NotFound());
        }

/* =========================================================
   🔐 HTTPS + HSTS
   ========================================================= */
app.UseHsts();
app.UseHttpsRedirection();

/* =========================================================
   🔐 SECURITY HEADERS
   =========================================================
   - XSS protection, clickjacking
   - Strict transport security
*/
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;

    // ❌ Prevents MIME-type sniffing attacks.
    // Forces the browser to respect the Content-Type sent by the server,
    // preventing HTML or JSON from being executed as JavaScript.
    // ➜ Protects against XSS and file-based attacks.
    headers["X-Content-Type-Options"] = "nosniff";

    // ❌ Prevents Clickjacking attacks.
    // Disallows this application from being embedded inside any iframe or frame.
    // ➜ Mandatory for banking login and transaction pages.
    headers["X-Frame-Options"] = "DENY";

    // ❌ Prevents leaking sensitive URLs via the Referer header.
    // No referrer information will be sent to external websites.
    // ➜ Protects tokens, session IDs, and internal paths.
    headers["Referrer-Policy"] = "no-referrer";

    // ❌ Legacy protection against reflected XSS attacks.
    // Mostly ignored by modern browsers, but kept for backward compatibility.
    // ➜ Primary XSS protection is enforced through CSP.
    headers["X-XSS-Protection"] = "1; mode=block";

    // ❌ Content Security Policy (CSP)
    // Defines which resources the browser is allowed to load.
    headers["Content-Security-Policy"] =
        // Allows resources only from the same origin
        "default-src 'self'; " +

        // Allows JavaScript execution only from the same origin
        // ➜ Blocks injected and malicious scripts
        "script-src 'self'; " +

        // Allows API, AJAX, and WebSocket connections only to the same origin
        // ➜ Prevents data exfiltration to external servers
        "connect-src 'self'; " +

        // Allows images only from the same origin
        // ➜ Blocks tracking pixels and external image abuse
        "img-src 'self'; " +

        // Completely blocks plugins such as Flash, ActiveX, and other legacy objects
        // ➜ Prevents legacy exploit vectors
        "object-src 'none'; " +

        // Prevents this application from being embedded inside frames
        // ➜ Additional clickjacking protection
        "frame-ancestors 'none'; " +

        // Prevents base URL manipulation attacks
        "base-uri 'self';";

    // ❌ HTTP Strict Transport Security (HSTS)
    // Forces browsers to communicate only over HTTPS for the next 2 years.
    // Applies to all subdomains and is eligible for browser preload lists.
    // ➜ Prevents SSL stripping and Man-in-the-Middle (MITM) attacks.
    headers["Strict-Transport-Security"] =
        "max-age=63072000; includeSubDomains; preload";

    // ❌ Permissions Policy
    // Explicitly disables access to camera, microphone, and geolocation
    // via browser or WebView JavaScript APIs.
    // ➜ Prevents silent spying and sensor abuse.
    headers["Permissions-Policy"] =
        "camera=(), microphone=(), geolocation=()";

    // ❌ Prevents caching of sensitive banking responses.
    // Ensures data is not stored in browser, proxy, or device caches.
    // ➜ Protects sensitive data on shared or stolen devices.
    headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
    headers["Pragma"] = "no-cache";

    // ❌ Removes server fingerprinting headers.
    // Prevents attackers from identifying the backend technology stack.
    // ➜ Reduces the risk of targeted attacks.
    headers.Remove("Server");
    headers.Remove("X-Powered-By");

    // Proceed to the next middleware in the pipeline
    await next();
});



/* =========================================================
   🚫 BLOCK TRACE & HEAD METHODS
   =========================================================
   - Prevent HTTP methods misuse
*/
app.Use(async (context, next) =>
{
    var method = context.Request.Method;

    if (method == HttpMethods.Trace || method == HttpMethods.Head)
    {
        context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
        await context.Response.WriteAsync("Method not allowed");
        return;
    }

    await next();
});

app.UseMiddleware<RequestContextMiddleware>();


/* =========================================================
   🔀 PIPELINE ORDER (IMPORTANT)
   ========================================================= */
app.UseCors("CorsPolicy");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<ExceptionMiddleware>();

app.MapControllers();

app.Run();
