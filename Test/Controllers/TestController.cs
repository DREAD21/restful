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
using Newtonsoft.Json;


namespace Test.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)]
    public class TestController : Controller
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
            //Validate the User Credentials      
            //Demo Purpose, I have Passed HardCoded User Information      
            //if (login.UserName == "Jay")
            //{
            //    user = new LoginModel { UserName = "Jay", Password = "123456" };
            //}
            return await db.Users.FirstOrDefaultAsync(x => x.Login == login.Login);
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
            if (db.Users.FirstOrDefault(x => x.Login == data.Login) == null)
            {
                return response = BadRequest(new { Message = "Wrong Login or Password" });
            }
            else
            {
                if (db.Users.FirstOrDefault(x => x.Login == data.Login).Password != data.Password)
                    return response = BadRequest(new { Message = "Wrong Login or Password" });
            }
            var user = await AuthenticateUser(data);
            var identity = GetIdentity(data.Login);
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
        public string Get()
        {
            return User.Identity.Name.ToString();
        }


        #endregion

        #region Create

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
        /// <param name="Birthday"></param>
        /// <response code="403">You are not an admin</response>
        /// <response code="401">not authorized</response>
        /// <response code="400">Wrong data</response>
        [Authorize(Roles = "True")]
        [HttpPost]
        public async Task<IActionResult> CreateUser([Required][RegularExpression("[0-9a-zA-Z]+", ErrorMessage = "Некорректное имя")] string Login, [Required][RegularExpression("[a-zA-Z0-9]+", ErrorMessage = "Некорректный пароль")] string Password, [Required][RegularExpression("[a-zA-Zа-яА-Я]+", ErrorMessage = "Некорректное имя")] string Name, [Required] bool Admin, [Required][RegularExpression("[0-2]")] int Gender, DateTime? Birthday)
        {
            IActionResult response = null;
            if (db.Users.FirstOrDefault(x => x.Login == Login) != null)
            {
                return response = BadRequest(new { Message = "This login already exists" });
            }

            db.Users.Add(new Models.User { Guid = (Guid)guid, Login = Login, Password = Password, Name = Name, Admin = Admin, Gender = Gender, CreatedOn = d, CreatedBy = User.Identity.Name, Birthday = Birthday });
            await db.SaveChangesAsync();
            return response = Ok(new { Message = "Success" });


        }

        #endregion

        #endregion

        #region Read

        #region UserRequest
        /// <summary>
        /// UserRequest
        /// </summary>
        /// <remarks>
        /// Доступно только самому пользователю, если он активен
        /// </remarks>
        /// <param name="Login">Логин</param>
        /// <param name="password">Пароль</param>
        /// <response code="400">Wrong Login</response>
        /// <response code="401">not authorized</response>
        [HttpGet, Route("Use Request")]
        public async Task<IActionResult> UserRequest([Required] string Login, [Required] string password)
        { 
            var res = await db.Users.FirstOrDefaultAsync(x => x.Login == User.Identity.Name);
            if (res.RevokedOn != null)
                return BadRequest(new { Message = "User is not active" });
            //if (res == null)
            //    return BadRequest(new { Message = "Wrong Login or Password" });

            //if (password != res.Password)
            //    return BadRequest(new { Message = "Wrong Login or Password" });
            if (Login != User.Identity.Name || password != res.Password)
            {
                return BadRequest(new { Message="Wrong Login or Password"});
            }

            return Json(res);
        }


        #endregion

        #region Age
        /// <summary>
        /// Select a user by age
        /// </summary>
        /// <remarks>
        /// Доступно только администратору
        /// </remarks>
        /// <param name="age">Возраст</param>
        /// <response code="403">not an admin</response>
        [HttpGet, Route("Age")]
        [Authorize(Roles ="True")]
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

        #region LoginRequest

        /// <summary>
        /// Select a user by age
        /// </summary>
        /// <remarks>
        /// Доступно только администратору
        /// </remarks>
        /// <param name="Login">Login</param>
        /// <response code="403">Not an admin</response>
        /// <response code="400">Wrong Login</response>
        [Authorize(Roles = "True")]
        [HttpGet, Route("LoginRequest")]
        public IActionResult LoginRequest([Required][RegularExpression("[0-9a-zA-Z]+", ErrorMessage = "Некорректное имя")] string Login)
        {
            IActionResult response = null;
            var user = db.Users.FirstOrDefault(x => x.Login == Login);
            if (user == null)
            {
                return response = BadRequest(new { Message = "Wrong Login" });
            }
            var some = new { user.Name, user.Gender, user.Birthday, user.RevokedOn };
            return Json(some);

        }
        #endregion

        #endregion

        #region Delete
        /// <summary>
        /// Delete a user by Login
        /// </summary>
        /// <remarks>
        /// Доступно только администратору
        /// </remarks>
        /// <param name="Login">Login</param>
        /// <param name="Type">True - полное удаление, False - мягкое удаление</param>
        /// <response code="403">Not an admin</response>
        /// <response code="400">Wrong Login</response>
        [HttpDelete]
        [Authorize(Roles ="True")]
        public IActionResult DeleteUser([Required]string Login, [Required]bool Type)
        {
            IActionResult response;
            User _user = db.Users.FirstOrDefault(x => x.Login == Login);
            if (_user == null)
                return response = BadRequest(new { Message = "Wrond Login" });
            if (Type == true)
            {
                db.Users.Remove(_user);
                db.SaveChanges();
            }
            else
            {
                var admin_name = User.Identity.Name.ToString();
                _user.RevokedBy = admin_name;
                _user.RevokedOn = d;
                db.SaveChanges();
            }
            return response = Ok(new { Message = "Success" });
        }


        #endregion

        #region Update-2
        /// <summary>
        /// Delete a user by Login
        /// </summary>
        /// <remarks>
        /// Доступно только администратору
        /// </remarks>
        /// <param name="Login">Login</param>
        /// <response code="403">Not an admin</response>
        /// <response code="400">Wrong Login</response>
        [HttpPut]
        [Authorize(Roles = "True"), Route("Update-2")]
        public IActionResult Upate2([Required] string Login)
        {
            IActionResult response;
            User _user = db.Users.FirstOrDefault(x => x.Login == Login);
            if (_user == null)
                return response = BadRequest(new { Message = "Wrond Login" });
            if (_user.RevokedOn == null || _user.RevokedBy == null)
            {
                return response = BadRequest(new { Message = "This user has not been deleted" });
            }
            _user.RevokedBy = null;
            _user.RevokedOn = null;
            db.SaveChanges();
            return response = Ok(new { Message = "Success"});
        }

        #endregion

        //#region Update
        //public async Task<IActionResult> UpdatePassword([Required]string new_pass, string login)
        //{
        //    IActionResult response;


        //    return null;
        //} 


        //#endregion
    }

}

