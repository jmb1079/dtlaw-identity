using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Dtlaw.Identity.Model
{
    public class UserDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}