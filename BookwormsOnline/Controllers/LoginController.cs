//using BookwormsOnline;
//using Microsoft.AspNetCore.Mvc;

//public class AccountController : Controller
//{
//    private readonly MyDbContext _context;

//    public AccountController(MyDbContext context)
//    {
//        _context = context;
//    }

//    [HttpPost]
//    public async Task<IActionResult> Login(LoginModel loginModel)
//    {
//        if (ModelState.IsValid)
//        {
//            // Check login credentials (this is a simplified version)
//            var user = await _context.Users
//                .FirstOrDefaultAsync(u => u.Email == loginModel.Email && u.Password == loginModel.Password);

//            if (user != null)
//            {
//                // Successful login
//                return RedirectToAction("RegisterSuccess", "Users"); // Redirect to RegisterSuccess in Users controller
//            }
//            else
//            {
//                // Invalid credentials
//                ModelState.AddModelError("", "Invalid email or password.");
//            }
//        }

//        return View(loginModel);
//    }
//}
