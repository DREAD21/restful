using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
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
        private IConfiguration _config;
        public TestController(UsersContext context, IConfiguration config)
        {
            db = context;
            _config = config;
        }
       
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
        [Authorize(Roles = "True"), Route("Create User")]
        [HttpPost]
        public async Task<IActionResult> CreateUser([Required][RegularExpression("[0-9a-zA-Z]+", ErrorMessage = "Некорректное имя")] string Login, [Required][RegularExpression("[a-zA-Z0-9]+", ErrorMessage = "Некорректный пароль")] string Password, [Required][RegularExpression("[a-zA-Zа-яА-Я]+", ErrorMessage = "Некорректное имя")] string Name, [Required] bool Admin, [Required][RegularExpression("[0-2]")] int Gender, DateTime? Birthday)
        {

            if (db.Users.FirstOrDefault(x => x.Login == Login) != null)
            {
                return BadRequest(new { Message = "This login already exists" });
            }

            db.Users.Add(new Models.User { Guid = (Guid)guid, Login = Login, Password = Password, Name = Name, Admin = Admin, Gender = Gender, CreatedOn = d, CreatedBy = User.Identity.Name, Birthday = Birthday });
            await db.SaveChangesAsync();
            return Ok(new { Message = "Success" });
        }

        #endregion

        #endregion

        #region Read

        #region UserRequest
        /// <summary>
        /// Запрос пользователя по логину и паролю
        /// </summary>
        /// <remarks>
        /// Доступно только самому пользователю, если он активен
        /// </remarks>
        /// <param name="Login">Логин</param>
        /// <param name="password">Пароль</param>
        /// <response code="400">Wrong Login</response>
        /// <response code="401">not authorized</response>
        [HttpGet, Route("User Request")]
        public async Task<IActionResult> UserRequest([Required] string Login, [Required] string password)
        {
            var res = await db.Users.FirstOrDefaultAsync(x => x.Login == User.Identity.Name);
            if (Login != User.Identity.Name || password != res.Password)
            {
                return BadRequest(new { Message = "Wrong Login or Password" });
            }

            if (res.RevokedOn != null)
                return BadRequest(new { Message = "User is not active" });
            //if (res == null)
            //    return BadRequest(new { Message = "Wrong Login or Password" });

            //if (password != res.Password)
            //    return BadRequest(new { Message = "Wrong Login or Password" });


            return Json(res);
        }


        #endregion

        #region Age
        /// <summary>
        /// Запрос всех пользователей старше определённого возраста
        /// </summary>
        /// <remarks>
        /// Доступно только администратору
        /// </remarks>
        /// <param name="age">Возраст</param>
        /// <response code="403">not an admin</response>
        [HttpGet, Route("Age")]
        [Authorize(Roles = "True")]
        public IActionResult Age([Required, FromQuery] int age)
        {
            year = d.Year;
            month = d.Month;
            day = d.Day;
            int res = year - age;
            DateTime d1 = new DateTime(res, month, day);
            var selected = from p in db.Users
                           where p.Birthday < d1
                           select p;
            return Json(selected);

        }
        #endregion

        #region RealUsers
        /// <summary>
        /// Запрос списка всех активных пользователей,
        /// </summary>
        /// <remarks>
        /// Доступно только admin
        /// </remarks>
        /// <response code="401">not authorized</response>
        /// <response code="403">You are not an admin</response>
        [HttpGet]
        [Authorize(Roles = "True")]
        public IActionResult Realusers()
        {
            var selected = from p in db.Users
                           where p.RevokedOn == null
                           orderby p.CreatedOn
                           select p;
            return Json(selected);
        }
        #endregion

        #region LoginRequest

        /// <summary>
        /// Запрос пользователя по логину
        /// </summary>
        /// <remarks>
        /// Доступно только администратору
        /// </remarks>
        /// <param name="Login">Login</param>
        /// <response code="403">Not an admin</response>
        /// <response code="400">Wrong Login</response>
        [Authorize(Roles = "True")]
        [HttpGet, Route("Login request")]
        public async Task<IActionResult> LoginRequest([Required][RegularExpression("[0-9a-zA-Z]+", ErrorMessage = "Некорректное имя")] string Login)
        {

            var user = await db.Users.FirstOrDefaultAsync(x => x.Login == Login);
            if (user == null)
            {
                return BadRequest(new { Message = "Wrong Login" });
            }
            var some = new { user.Name, user.Gender, user.Birthday, user.RevokedOn };
            return Json(some);

        }
        #endregion

        #endregion

        #region Delete
        /// <summary>
        /// Удаление пользователя по логину полное или мягкое
        /// </summary>
        /// <remarks>
        /// Доступно только администратору
        /// </remarks>
        /// <param name="Login">Login</param>
        /// <param name="Type">True - полное удаление, False - мягкое удаление</param>
        /// <response code="403">Not an admin</response>
        /// <response code="400">Wrong Login</response>
        [HttpDelete]
        [Authorize(Roles = "True")]
        public async Task<IActionResult> DeleteUser([Required] string Login, [Required] bool Type)
        {
            User _user = db.Users.FirstOrDefault(x => x.Login == Login);
            if (_user == null)
                return BadRequest(new { Message = "Wrond Login" });
            if (Type == true)
            {
                db.Users.Remove(_user);
                await db.SaveChangesAsync();
            }
            else
            {
                var admin_name = User.Identity.Name.ToString();
                _user.RevokedBy = admin_name;
                _user.RevokedOn = d;
                await db.SaveChangesAsync();
            }
            return Ok(new { Message = "Success" });
        }


        #endregion

        #region Update-2
        /// <summary>
        /// Восстановление пользователя - Очистка полей (RevokedOn, RevokedBy)
        /// </summary>
        /// <remarks>
        /// Доступно только администратору
        /// </remarks>
        /// <param name="Login">Login</param>
        /// <response code="403">Not an admin</response>
        /// <response code="400">Wrong Login</response>
        [HttpPut]
        [Authorize(Roles = "True"), Route("Update-2")]
        public async Task<IActionResult> Upate2([Required] string Login)
        {

            User _user = db.Users.FirstOrDefault(x => x.Login == Login);
            if (_user == null)
                return BadRequest(new { Message = "Wrond Login" });
            if (_user.RevokedOn == null || _user.RevokedBy == null)
            {
                return BadRequest(new { Message = "This user has not been deleted" });
            }
            _user.RevokedBy = null;
            _user.RevokedOn = null;
            await db.SaveChangesAsync();
            return Ok(new { Message = "Success" });
        }

        #endregion

        #region Update


        #region Update_Password
        /// <summary>
        /// Изменение пароля
        /// </summary>
        /// <remarks>
        /// Доступно либо саммому пользователю, либо администратору
        /// </remarks>
        /// <param name="login">Логин пользователя, для которого происходит смена пароля</param>
        /// <param name="new_pass">Новый пароль</param>
        /// <response code="403">Not an admin</response>
        /// <response code="400">Wrong Login</response>
        [HttpPut]
        [Route("Update Password")]
        public async Task<IActionResult> UpdatePassword([Required] string login, [Required][RegularExpression("[a-zA-Z0-9]+", ErrorMessage = "Некорректный пароль")] string new_pass)
        {
            var LoginUser = User.Identity.Name;
            if (db.Users.FirstOrDefault(x => x.Login == LoginUser).Admin)
            {
                if (db.Users.FirstOrDefault(x => x.Login == login) != null)
                {
                    User _user = await db.Users.FirstOrDefaultAsync(x => x.Login == login);
                    _user.Password = new_pass;
                    await db.SaveChangesAsync();
                }
                else
                {
                    return BadRequest(new { Message = "Wrong Login" });
                }
            }
            else
            {
                if (db.Users.FirstOrDefault(x => x.Login == LoginUser).RevokedOn != null)
                {
                    return BadRequest(new { Message = "Revoked On is not null" });
                }
                if (login != LoginUser)
                {
                    return BadRequest(new { Message = "A non-administrator user can only change his password" });
                }
                User _user = await db.Users.FirstOrDefaultAsync(x => x.Login == LoginUser);
                _user.Password = new_pass;
                await db.SaveChangesAsync();
            }
            return Ok(new { Message = "Success" });
        }
        #endregion

        #region Update_Login
        /// <summary>
        /// Изменение логина
        /// </summary>
        /// <remarks>
        /// Доступно либо саммому пользователю, либо администратору
        /// </remarks>
        /// <param name="login">Логин пользователя, для которого происходит смена пароля</param>
        /// <param name="new_login">Новый логин</param>
        /// <response code="403">Not an admin</response>
        /// <response code="400">Wrong Login</response>
        [HttpPut]
        [Route("Update Login")]
        public async Task<IActionResult> UpdateLogin([Required] string login, [Required][RegularExpression("[a-zA-Z0-9]+", ErrorMessage = "Некорректный логин")] string new_login)
        {          
            if (db.Users.FirstOrDefault(x => x.Login == User.Identity.Name).Admin)
            {
                if (db.Users.FirstOrDefault(x => x.Login == login) != null)
                {
                    User _user = await db.Users.FirstOrDefaultAsync(x => x.Login == login);
                    if (await db.Users.FirstOrDefaultAsync(x => x.Login == new_login) != null)
                    {
                        return BadRequest(new { Message = "This login is already exists" });
                    }
                    _user.Login = new_login;
                    await db.SaveChangesAsync();
                }
                else
                {
                    return BadRequest(new { Message = "Wrong Login" });
                }
            }
            else
            {
                if (db.Users.FirstOrDefault(x => x.Login == login).RevokedOn != null)
                {
                    return BadRequest(new { Message = "Revoked On is not null" });
                }
                if (login != User.Identity.Name)
                {
                    return BadRequest(new { Message = "A non-administrator user can only change his password" });
                }
                if (await db.Users.FirstOrDefaultAsync(x => x.Login == new_login) != null)
                {
                    return BadRequest(new { Message = "This login is already exists" });
                }
                User _user = await db.Users.FirstOrDefaultAsync(x => x.Login == login);
                _user.Login = new_login;
                await db.SaveChangesAsync();
            }
            return Ok(new { Message = "Success" });

        }


        #endregion

        #region Update_Name_Birthday_Gender
        /// <summary>
        /// Изменение имени, пола или даты рождения пользователя
        /// </summary>
        /// <remarks>
        /// Доступно либо саммому пользователю, либо администратору
        /// </remarks>
        /// <param name="login">Логин пользователя, для которого происходит смена пароля</param>
        /// <param name="Name">Новое имя </param>
        /// <param name="Birtday">Новая дата рождения</param>
        /// <param name="Gender">новый гендер</param>
        /// <response code="403">Not an admin</response>
        /// <response code="400">Wrong Login</response>
        [Route("Update Name, Birthday or Gender")]
        [HttpPut]
        public async Task<IActionResult> Update_Name_Birthday_Gender([Required] string login, [RegularExpression(@"[a-zA-Zа-яА-Я]+", ErrorMessage = "Некорректное имя")] string Name, DateTime? Birtday, [RegularExpression(@"[0,1,2]")] int? Gender)
        {
            var LoginUser = User.Identity.Name;
            if (db.Users.FirstOrDefault(x => x.Login == LoginUser).Admin)
            {
                if (db.Users.FirstOrDefault(x => x.Login == login) != null)
                {
                    User _user = await db.Users.FirstOrDefaultAsync(x => x.Login == login);
                    if (Name != null)
                    {
                        _user.Name = Name;
                    }
                    if (Birtday != null)
                    {
                        _user.Birthday = Birtday;
                    }
                    if (Gender != null)
                    {
                        _user.Gender = (int)Gender;
                    }

                    await db.SaveChangesAsync();
                }
                else
                {
                    return BadRequest(new { Message = "Wrong Login" });
                }
            }
            else
            {
                if (db.Users.FirstOrDefault(x => x.Login == LoginUser).RevokedOn != null)
                {
                    return BadRequest(new { Message = "Revoked On is not null" });
                }
                if (login != LoginUser)
                {
                    return BadRequest(new { Message = "A non-administrator user can only change his password" });
                }
                User _user = await db.Users.FirstOrDefaultAsync(x => x.Login == login);
                if (Name != null)
                {
                    _user.Name = Name;
                }
                if (Birtday != null)
                {
                    _user.Birthday = Birtday;
                }
                if (Gender != null)
                {
                    _user.Gender = (int)Gender;
                }

                await db.SaveChangesAsync();
            }
            return Ok(new { Message = "Success" });
        }

        #endregion


        #endregion
    }



   
}

