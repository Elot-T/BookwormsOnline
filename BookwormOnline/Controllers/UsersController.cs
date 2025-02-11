using Microsoft.AspNetCore.Mvc;
using BookwormsOnline.Models;
using Microsoft.EntityFrameworkCore;

namespace BookwormsOnline.Controllers
{
    public class UsersController : Controller
    {
        private readonly MyDbContext _context;

        public UsersController(MyDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View(new User());
        }

        [HttpPost]
        public async Task<IActionResult> Register(User user, IFormFile? photo)
        {
            if (ModelState.IsValid)
            {
                // Handle photo upload
                if (photo != null)
                {
                    var uploadsFolder = Path.Combine("wwwroot", "images");
                    var uniqueFileName = $"{Guid.NewGuid()}_{photo.FileName}";
                    var photoPath = Path.Combine(uploadsFolder, uniqueFileName);

                    using var fileStream = new FileStream(photoPath, FileMode.Create);
                    await photo.CopyToAsync(fileStream);

                    user.PhotoPath = $"/images/{uniqueFileName}";
                }

                // Save user to the database
                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                return RedirectToAction("RegisterSuccess");
            }

            return View(user);
        }

        [HttpGet]
        public IActionResult RegisterSuccess()
        {
            return View();
        }
    }
}
