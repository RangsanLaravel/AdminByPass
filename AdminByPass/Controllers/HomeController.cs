using AdminByPass.Models;
using CryptoHelper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


namespace AdminByPass.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly string _connectionString = "Data Source=localhost;Initial Catalog=ISEE;User ID=sa;Password=25J@nP@$$w0rd";
        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Index(LoginViewModel model)
        {
            try
            {               
                var result = UserLogin(model.Username, model.Password, true);
                if (string.IsNullOrWhiteSpace(result))
                    ViewBag.LoginFail = "User Password invalid";
                else
                {
                    ViewBag.Token = result;
                }                   
                // If we got this far, something failed, redisplay form
                return View(model);
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
                ViewBag.Stack = ex.StackTrace;
                return View("Error");
            }
            
        }
        
        [Authorize]
        [HttpPost]
        public IActionResult Privacy([FromBody]LoginViewModel model)
        {
           var result = UserLogin(model.Username, "",false);
            string success = string.Empty;
            if (!string.IsNullOrWhiteSpace(result))
                success = "ByPass Success";
            else
                success = "username Is valid";
            return Json(new { Message = success });
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private string UserLogin(string username, string password, bool isLogin)
        {
            User user = null;
            var query = @$"SELECT user_id, em.user_name, em.password, em.fullname, em.lastname, em.position, 
                             po.position_description, po.security_level
                      FROM [ISEE].[dbo].[tbm_employee] em 
                      LEFT JOIN [ISEE].[dbo].[tbm_employee_position] po on em.position = po.position_code
                      WHERE UPPER(em.user_name) = @username
                      AND em.status = 1 
                      AND po.status = 1
                      {(isLogin? " AND em.position='CK'" : "")}
";

            using (var connection = new SqlConnection(_connectionString))
            {
                 connection.Open();

                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.Add(new SqlParameter("@username", SqlDbType.VarChar) { Value = username.ToUpper() });

                    using (var reader =  command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            // Assuming you want to check the password in your application
                            var dbPassword = reader["password"].ToString();
                            user = new User
                            {
                                UserId = Convert.ToInt32(reader["user_id"]),
                                UserName = reader["user_name"].ToString(),
                                FullName = reader["fullname"].ToString(),
                                LastName = reader["lastname"].ToString(),
                                Position = reader["position"].ToString(),
                                PositionDescription = reader["position_description"].ToString(),
                                SecurityLevel = Convert.ToInt32(reader["security_level"])
                            };
                            if (isLogin)
                            {
                                if (!Crypto.VerifyHashedPassword(dbPassword, password))
                                    return string.Empty;
                                else
                                {
                                   var token = BuildToken(user);
                                    return token;

                                }

                            }
                            else
                            {
                              var token =  BuildToken(user);
                                return token; 
                            }
                               
                        }
                    }
                }
            }
            return string.Empty;
        }

        private string BuildToken(User employee)
        {
            // key is case-sensitive
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.Sub, "itmpbenz@gmail.com"),
                new Claim("id", employee.UserId.ToString()),
                new Claim("username", employee.UserName),
            //ใช้ role เพื่อลดการโหลดดาต้าเบส
                new Claim(ClaimTypes.Role, employee.Position)
            };
            var expires = DateTime.Now.AddDays(Convert.ToDouble(1));
            //แก้วันที่ได้
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("I SEE SERVICE WEBAPI AND PROVIDE"));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "ISEE",
                audience: "http://ISEE.com",
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public class User
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string FullName { get; set; }
        public string LastName { get; set; }
        public string Position { get; set; }
        public string PositionDescription { get; set; }
        public int SecurityLevel { get; set; }
    }
}
