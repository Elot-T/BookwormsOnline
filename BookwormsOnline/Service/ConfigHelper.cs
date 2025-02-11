using Microsoft.Extensions.Configuration;
using System.IO;

public static class ConfigHelper
{
    private static IConfigurationRoot _config;

    static ConfigHelper()
    {
        _config = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory()) // Ensure the path is correct
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();
    }

    public static string GetEncryptionKey()
    {
        return _config["Encryption:Key"] ?? throw new Exception("Encryption key not found in appsettings.json!");
    }
}
