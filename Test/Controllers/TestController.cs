using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Test.Models;
using System.Security.Claims;

namespace Test.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)]
    public class TestController : ControllerBase
    {
        UsersContext db;
        public object guid = Guid.NewGuid();
        public DateTime d = DateTime.Now;
        public int year;
        public int month;
        public int day;
        public TestController(UsersContext context)
        {
            db = context;
        }



    }
    public class AuthenticateController : TestController
    {
        #region Property  
        /// <summary>  
        /// Property Declaration  
        /// </summary>  
        /// <param name="data"></param>  
        /// <returns></returns>  
        private IConfiguration _config;
        UsersContext db;
        #endregion

        #region Contructor Injector  
        /// <summary>  
        /// Constructor Injection to access all methods or simply DI(Dependency Injection)  
        /// </summary>  
        public AuthenticateController(IConfiguration config, UsersContext context) : base(context)
        {
            _config = config;
            db = context;
        }
        #endregion

        #region GenerateJWT  
        /// <summary>  
        /// Generate Json Web Token Method  
        /// </summary>  
        /// <param name="userInfo"></param>  
        /// <returns></returns>  
        private string GenerateJSONWebToken(ClaimsIdentity identity)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            
            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
              _config["Jwt:Issuer"],
              expires: DateTime.Now.AddMinutes(120),
              claims: identity.Claims,
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        #endregion

        #region UserRole
        private ClaimsIdentity GetIdentity(string username)
        {
            User user = db.Users.FirstOrDefault(x => x.Login == username);
            
            var claims = new List<Claim>
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, user.Login),
                new Claim(ClaimsIdentity.DefaultRoleClaimType, user.Admin.ToString())
            };
            ClaimsIdentity claimsIdentity =
            new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                ClaimsIdentity.DefaultRoleClaimType);
            return claimsIdentity;
            

        }
        #endregion

        #region AuthenticateUser  
        /// <summary>  
        /// Hardcoded the User authentication  
        /// </summary>  
        /// <param name="login"></param>  
        /// <returns></returns>  
        private async Task<User> AuthenticateUser(LoginModel login)
        {
            db.Users.FirstOrDefault(x => x.Login == login.UserName);

            //Validate the User Credentials      
            //Demo Purpose, I have Passed HardCoded User Information      
            //if (login.UserName == "Jay")
            //{
            //    user = new LoginModel { UserName = "Jay", Password = "123456" };
            //}
            return db.Users.FirstOrDefault(x => x.Login == login.UserName); 
        }
        #endregion

        #region Login Validation  
        /// <summary>  
        /// Login Authenticaton using JWT Token Authentication  
        /// </summary>  
        /// <param name="data"></param>  
        /// <returns></returns>  
        /// <response code="400">Wrong Login or Password</response>
        [AllowAnonymous]
        [HttpPost(nameof(Login))]
        public async Task<IActionResult> Login([FromForm] LoginModel data)
        {
            IActionResult response = Unauthorized();
            if (db.Users.FirstOrDefault(x => x.Login == data.UserName) == null)
            {
                return response = BadRequest(new { Message = "Wrong Login or Password" });
            }
            else
            {
                if (db.Users.FirstOrDefault(x => x.Login == data.UserName).Password != data.Password)
                    return response = BadRequest(new { Message = "Wrong Login or Password"});
            }
            var user = await AuthenticateUser(data);
            var identity = GetIdentity(data.UserName);
            if (data != null)
            {
                var tokenString = GenerateJSONWebToken(identity);
                response = Ok(new { Token = tokenString, Message = "Success" });
            }
            return response;
        }
        #endregion

        #region Get  
        /// <summary>  
        /// Authorize the Method  
        /// </summary>  
        /// <returns></returns>  
        [HttpGet(nameof(Get))]
        public async Task<IEnumerable<string>> Get()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");

            return new string[] { accessToken };
        }


        #endregion

        #region CreateUser
        /// <summary>
        /// Create a new User
        /// </summary>
        /// <remarks>
        /// Создание пользователя, доступно только admin
        /// </remarks>
        /// <param name="Login">Запрещены все символы кроме латинских букв и цифр</param>
        /// <param name="Password">Запрещены все символы кроме латинских букв и цифр</param>
        /// <param name="Name">Запрещены все символы кроме латинских и русских букв</param>
        /// <param name="Admin"></param>
        /// <param name="Gender">1 - мужчина, 0 - женщина, 2 - неизвестно</param>
        /// <response code="403">You are not an admin</response>
        /// <response code="401">not authorized</response>
        [Authorize(Roles = "True")]
        [HttpPost]
        public void CreateUser([Required][RegularExpression("[0-9a-zA-Z]+", ErrorMessage = "Некорректное имя")] string Login, [Required][RegularExpression("[a-zA-Z0-9]+", ErrorMessage = "Некорректный пароль")] string Password, [Required][RegularExpression("[a-zA-Zа-яА-Я]+", ErrorMessage = "Некорректное имя")] string Name, [Required] bool Admin, [Required][RegularExpression("[0-2]")] int Gender, DateTime Birthday)
        {
            if (ModelState.IsValid)
            {
                db.Users.Add(new Models.User { Guid = (Guid)guid, Login = Login, Password = Password, Name = Name, Admin = Admin, Gender = Gender, CreatedOn = d, CreatedBy = "Admin", Birthday = Birthday });
                db.SaveChanges();
            }
        }

        #endregion

        #region RealUsers
        /// <summary>
        /// Requesting a list of all active users
        /// </summary>
        /// <remarks>
        /// Доступно только admin
        /// </remarks>
        /// <response code="401">not authorized</response>
        /// <response code="403">You are not an admin</response>
        [HttpGet]
        [Authorize(Roles = "True")]
        public IQueryable<User> Realusers()
        {
            var selected = from p in db.Users
                           where p.RevokedOn == null
                           orderby p.CreatedOn
                           select p;

            return selected;
        }
        #endregion

        /// <summary>
        /// Update the user
        /// </summary>
        /// <remarks>
        /// Может обновить либо сам пользователь, либо администратор
        /// </remarks>
        /// <param name="Name">Запрещены все символы кроме латинских и русских букв</param>
        /// <param name="Gender">1 - мужчина, 0 - женщина, 2 - неизвестно</param>
        /// <param name="Birthday">Формат date</param>
        /// <response code="401">not authorized</response>
        [HttpPut]
        //[ProducesResponseType(StatusCodes.Status201Created)]
        //[ProducesResponseType(StatusCodes.Status400BadRequest)]
        public void UpdateUser([RegularExpression("[a-zA-Zа-яА-Я]+", ErrorMessage = "Некорректное имя")] string Name, bool? Gender, DateTime? Birthday)
        {
            if (!string.IsNullOrEmpty(Name))
            {
                db.Update(Name);
                db.SaveChanges();
            }
            if (Gender != null)
            {
                db.Update(Gender);
            }
            if (Birthday != null)
            {
                db.Update(Birthday);
            }

        }

        #region Age
        [HttpGet, Route("Age")]
        public IEnumerable<User> Age([Required, FromQuery] int age)
        {

            year = d.Year;
            month = d.Month;
            day = d.Day;
            int res = year - age;
            DateTime d1 = new DateTime(res, month, day);
            var selected = from p in db.Users
                           where p.Birthday < d1
                           select p;
            return selected;

        }





        #endregion


    }




}

