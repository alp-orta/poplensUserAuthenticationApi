﻿using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using poplensUserAuthenticationApi.Models;

namespace poplensUserAuthenticationApi.Data {
    public class UserDbContext : IdentityDbContext<User> {
        public UserDbContext(DbContextOptions<UserDbContext> options) : base(options) {
        }
    }
}
