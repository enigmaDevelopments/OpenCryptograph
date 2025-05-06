using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using Website.Models;
using OpenCryptograph;
using System.Numerics;
using System.Collections.Generic;

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
        Dictionary<BigInteger, Info> users = new Dictionary<BigInteger, Info>();
        private readonly ILogger<HomeController> _logger;
        
        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        public IActionResult SignIn(string username, string password)
        {
            BigInteger usernameHash = Hash.Shake128(username, 2048);
            BigInteger passwordHash = Hash.Shake128(username + password, 2048);
            if (!users.ContainsKey(usernameHash)) {
                Key key = new Key(Hash.Shake128(username + password + username, 1024));
                users.Add(usernameHash, new Info(passwordHash, key.publicKey));
            }
            return View("Index");
        }
        public IActionResult Send(string username, string message)
        {
            Console.WriteLine(username);
            Console.WriteLine(message);
            return View("Message");
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
