using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using poplensUserAuthenticationApi.Models;

namespace poplensUserAuthenticationApi.Data {
    public class UserDbContext : IdentityDbContext<User> {
        public UserDbContext(DbContextOptions<UserDbContext> options) : base(options) {
        }

        protected override void OnModelCreating(ModelBuilder builder) {
            base.OnModelCreating(builder);

            // Specify schema for Identity tables
            builder.Entity<User>()
                .ToTable("AspNetUsers", "public");  // Specify the schema here

            // Add more entities and their schema settings if necessary
        }
    }
}
