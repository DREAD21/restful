using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Test.Models
{
    public class User
    {
        [Required]
        [Key]
        public Guid Guid { get; set; }
        [Required]
        [Display(Name = ("Запрещены все символы кроме латинских букв и цифр"))]
        [RegularExpression(@"[0-9a-zA-Z]+", ErrorMessage = "Некорректный логин")]
        public string Login { get; set; }
        [Required]
        [Display(Name = ("Запрещены все символы кроме латинских букв и цифр"))]
        [RegularExpression(@"[a-zA-Z0-9]+", ErrorMessage = "Некорректный пароль")]
        public string Password { get; set; }
        [Required]
        [Display(Name = ("Запрещены все символы кроме латинских и русских букв"))]
        [RegularExpression(@"[a-zA-Zа-яА-Я]+", ErrorMessage = "Некорректное имя")]
        public string Name { get; set; }
        [Required]
        [RegularExpression(@"[0,1,2]")]
        public int Gender { get; set; }
        public DateTime? Birthday { get; set; }
        [Required]
        public bool Admin { get; set; }
        [Required]
        public DateTime CreatedOn { get; set; }
        [Required]
        public string CreatedBy { get; set; }
        public DateTime? ModifiedOn { get; set; }
        public string ModifiedBy { get; set; }
        public DateTime? RevokedOn { get; set; }
        public string RevokedBy { get; set; }

        public static implicit operator string(User v)
        {
            throw new NotImplementedException();
        }
    }
}
