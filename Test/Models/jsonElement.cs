using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace Test.Models
{
    public class jsonElement
    {
        [Required]
        public string Login { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string Name { get; set; }
        [Required]
        public int Gender { get; set; }
        public DateTime? Birthday { get; set; }
        [Required]
        public bool Admin { get; set; }
    }
}
