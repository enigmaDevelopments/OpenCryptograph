using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using Website.Models;
using OpenCryptograph;
using System.Numerics;
using System.Web;
namespace Website.Controllers
{
    class Info
    {
        public readonly BigInteger password;
        public readonly BigInteger publicKey;
        public List<BigInteger> messages = new List<BigInteger>(); 
        public Info(BigInteger password, BigInteger publicKey)
        {
            this.password = password;
            this.publicKey = publicKey;
        }
    }
    public class HomeController : Controller
    {
        private static Dictionary<BigInteger, Info> users = new Dictionary<BigInteger, Info>();
        private readonly ILogger<HomeController> _logger;
        
        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        public IActionResult SignIn(string username, string password)
        {
            try
            {
                BigInteger usernameHash = Hash.Shake128(username, 2048);
                BigInteger passwordHash = Hash.Shake128(username + password, 2048);
                if (!users.ContainsKey(usernameHash))
                {
                    Key key = new Key(Hash.Shake128(username + password + username, 2048), 128);
                    users.Add(usernameHash, new Info(passwordHash, key.publicKey));
                }
                else if (users[usernameHash].password == passwordHash)
                    return Decrypt(new Key(Hash.Shake128(username + password + username, 2048), 128), users[usernameHash].messages);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            return View("Index");
        }
        public IActionResult Send(string username, string message)
        {
            try
            {
                //message = HttpUtility.HtmlEncode(message);
                BigInteger usernameHash = Hash.Shake128(username, 2048);
                if (users.ContainsKey(usernameHash))
                    users[usernameHash].messages.Add(Key.Encrypt(message, users[usernameHash].publicKey));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            return View("Message");
        }
        public IActionResult Decrypt(Key k,List<BigInteger> messages)
        {
            string output = "";
            foreach (BigInteger message in messages)
            {
                output += k.Decrypt(message) + "<br/>";
            }
            ViewBag.Messages = output;
            return View("Messages");
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }
        public IActionResult Message()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
