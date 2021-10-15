using CipherLib.Extensions;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Text.RegularExpressions;

namespace TestExample
{
    class Program
    {
        static void Main(string[] args)
        {
            //var password = GetPasswordFromEnvironmentVariable();
            //var password = GetPasswordFromFile();
            var password = "yourPassword";

            var configuration = new ConfigurationBuilder()
                .AddProtectedJsonFile(password, "appsettings.json", 
                    optional: false,
                    reloadOnChange: true,
                    new Regex("SomeApi:Secret"),
                    new Regex("DBConnection"))
                .Build();

            Console.WriteLine(JsonConvert.SerializeObject(Serialize(configuration), Formatting.Indented));
            Console.ReadKey();
        }
        private static JToken Serialize(IConfiguration config)
        {
            JObject obj = new JObject();

            foreach (var child in config.GetChildren())
            {
                if (child.Path.EndsWith(":0"))
                {
                    var arr = new JArray();

                    foreach (var arrayChild in config.GetChildren())
                    {
                        arr.Add(Serialize(arrayChild));
                    }

                    return arr;
                }
                else
                {
                    obj.Add(child.Key, Serialize(child));
                }
            }

            if (!obj.HasValues && config is IConfigurationSection section)
            {
                if (bool.TryParse(section.Value, out bool boolean))
                {
                    return new JValue(boolean);
                }
                else if (decimal.TryParse(section.Value, out decimal real))
                {
                    return new JValue(real);
                }
                else if (int.TryParse(section.Value, out int integer))
                {
                    return new JValue(integer);
                }
                else if (long.TryParse(section.Value, out long longInteger))
                {
                    return new JValue(longInteger);
                }

                return new JValue(section.Value);
            }

            return obj;
        }
    }
}
