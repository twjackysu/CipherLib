using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace CipherLib.Extensions
{
    // ref: https://stackoverflow.com/questions/36062670/encrypted-configuration-in-asp-net-core
    /// <summary>Provides extensions concerning <see cref="ProtectedJsonConfigurationProvider"/></summary>
    public static class ProtectedJsonConfigurationProviderExtensions
    {
        /// <summary>Adds a protected JSON file</summary>
        /// <param name="configurationBuilder"><see cref="IConfigurationBuilder"/> in which to apply the JSON file</param>
        /// <param name="password">Password used for decryption</param>
        /// <param name="path">The path to the file.</param>
        /// <param name="optional">Determines if loading the file is optional.</param>
        /// <param name="reloadOnChange">Determines whether the source will be loaded if the underlying file changes.</param>
        /// <returns>Returns the <see cref="IConfigurationBuilder"/></returns>
        /// <exception cref="ArgumentNullException"/>
        public static IConfigurationBuilder AddProtectedJsonFile(this IConfigurationBuilder configurationBuilder, string password, string path, bool optional, bool reloadOnChange = false, params Regex[] encryptedKeyExpressions)
        {
            var source = new ProtectedJsonConfigurationSource(password)
            {
                Path = path,
                Optional = optional,
                ReloadOnChange = reloadOnChange,
                EncryptedKeyExpressions = encryptedKeyExpressions
            };

            return configurationBuilder.Add(source);
        }
    }
    /// <summary>Represents a <see cref="ProtectedJsonConfigurationProvider"/> source</summary>
    public class ProtectedJsonConfigurationSource : JsonConfigurationSource
    {
        internal string Password { get; private set; }

        /// <summary>Represents a <see cref="ProtectedJsonConfigurationProvider"/> source</summary>
        /// <param name="password">Password used for decryption</param>
        /// <exception cref="ArgumentNullException"/>
        public ProtectedJsonConfigurationSource(string password)
        {
            this.Password = password ?? throw new ArgumentNullException();
        }

        /// <summary>Builds the configuration provider</summary>
        /// <param name="builder">Builder to build in</param>
        /// <returns>Returns the configuration provider</returns>
        public override IConfigurationProvider Build(IConfigurationBuilder builder)
        {
            EnsureDefaults(builder);
            return new ProtectedJsonConfigurationProvider(this);
        }

        /// <summary>Gets or sets the regular expressions that must match the keys to encrypt</summary>
        public IEnumerable<Regex> EncryptedKeyExpressions { get; set; }
    }
    /// <summary>Represents a provider that protects a JSON configuration file</summary>
    public partial class ProtectedJsonConfigurationProvider : JsonConfigurationProvider
    {
        private readonly ProtectedJsonConfigurationSource protectedSource;
        private readonly HashSet<string> encryptedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly byte[] encryptedPrefixBytes = Encoding.UTF8.GetBytes("!ENCRYPT!");

        /// <summary>Checks whether the given text is encrypted</summary>
        /// <param name="text">Text to check</param>
        /// <returns>Returns true in case the text is encrypted</returns>
        private bool isEncrypted(string text)
        {
            if (text == null) { return false; }

            //Decode the data in order to verify whether the decoded data starts with the expected prefix
            byte[] decodedBytes;
            try { decodedBytes = Convert.FromBase64String(text); }
            catch (FormatException) { return false; }

            return decodedBytes.Length >= encryptedPrefixBytes.Length
                && decodedBytes.AsSpan(0, encryptedPrefixBytes.Length).SequenceEqual(encryptedPrefixBytes);
        }

        /// <summary>Converts the given key to the JSON token path equivalent</summary>
        /// <param name="key">Key to convert</param>
        /// <returns>Returns the JSON token path equivalent</returns>
        private string convertToTokenPath(string key)
        {
            var jsonStringBuilder = new StringBuilder();

            //Split the key by ':'
            var keyParts = key.Split(':');
            for (var keyPartIndex = 0; keyPartIndex < keyParts.Length; keyPartIndex++)
            {
                var keyPart = keyParts[keyPartIndex];

                if (keyPart.All(char.IsDigit)) { jsonStringBuilder.Append('[').Append(keyPart).Append(']'); }
                else if (keyPartIndex > 0) { jsonStringBuilder.Append('.').Append(keyPart); }
                else { jsonStringBuilder.Append(keyPart); }
            }

            return jsonStringBuilder.ToString();
        }

        /// <summary>Writes the given encrypted key/values to the JSON oconfiguration file</summary>
        /// <param name="encryptedKeyValues">Encrypted key/values to write</param>
        private void writeValues(IDictionary<string, string> encryptedKeyValues)
        {
            try
            {
                if (encryptedKeyValues == null || encryptedKeyValues.Count == 0) { return; }

                using (var stream = new FileStream(this.protectedSource.Path, FileMode.Open, FileAccess.ReadWrite))
                {
                    JObject json;

                    using (var streamReader = new StreamReader(stream, Encoding.UTF8, true, 4096, true))
                    {
                        using (var jsonTextReader = new JsonTextReader(streamReader))
                        {
                            json = JObject.Load(jsonTextReader);

                            foreach (var encryptedKeyValue in encryptedKeyValues)
                            {
                                var tokenPath = this.convertToTokenPath(encryptedKeyValue.Key);
                                var value = json.SelectToken(tokenPath) as JValue;
                                if (value.Value != null) { value.Value = encryptedKeyValue.Value; }
                            }
                        }
                    }

                    stream.Seek(0, SeekOrigin.Begin);
                    using (var streamWriter = new StreamWriter(stream))
                    {
                        using (var jsonTextWriter = new JsonTextWriter(streamWriter) { Formatting = Formatting.Indented })
                        {
                            json.WriteTo(jsonTextWriter);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                throw new Exception($"Path: {protectedSource.Path}", exception);
            }
        }

        /// <summary>Represents a provider that protects a JSON configuration file</summary>
        /// <param name="source">Settings of the source</param>
        /// <see cref="ArgumentNullException"/>
        public ProtectedJsonConfigurationProvider(ProtectedJsonConfigurationSource source) : base(source)
        {
            this.protectedSource = source as ProtectedJsonConfigurationSource;
        }

        /// <summary>Loads the JSON data from the given <see cref="Stream"/></summary>
        /// <param name="stream"><see cref="Stream"/> to load</param>
        public override void Load(Stream stream)
        {
            //Call the base method first to ensure the data to be available
            base.Load(stream);

            var expressions = protectedSource.EncryptedKeyExpressions;
            if (expressions != null)
            {
                //Dictionary that contains the keys (and their encrypted value) that must be written to the JSON file
                var encryptedKeyValuesToWrite = new Dictionary<string, string>();

                //Iterate through the data in order to verify whether the keys that require to be encrypted, as indeed encrypted.
                //Copy the keys to a new string array in order to avoid a collection modified exception
                var keys = new string[this.Data.Keys.Count];
                this.Data.Keys.CopyTo(keys, 0);

                foreach (var key in keys)
                {
                    //Iterate through each expression in order to check whether the current key must be encrypted and is encrypted.
                    //If not then encrypt the value and overwrite the key
                    var value = this.Data[key];
                    if (!string.IsNullOrEmpty(value) && expressions.Any(e => e.IsMatch(key)))
                    {
                        this.encryptedKeys.Add(key);

                        //Verify whether the value is encrypted
                        if (!this.isEncrypted(value))
                        {
                            //var protectedValue = ProtectedData.Protect(Encoding.UTF8.GetBytes(value), protectedSource.Entropy, protectedSource.Scope);
                            var protectedValue = StringCipher.Encrypt(value, protectedSource.Password);
                            var protectedValueWithPrefix = new List<byte>(encryptedPrefixBytes);
                            protectedValueWithPrefix.AddRange(protectedValue);

                            //Convert the protected value to a base-64 string in order to mask the prefix (for cosmetic purposes)
                            //and overwrite the key with the encrypted value
                            var protectedBase64Value = Convert.ToBase64String(protectedValueWithPrefix.ToArray());
                            encryptedKeyValuesToWrite.Add(key, protectedBase64Value);
                            this.Data[key] = protectedBase64Value;
                        }
                    }
                }

                //Write the encrypted key/values to the JSON configuration file
                this.writeValues(encryptedKeyValuesToWrite);
            }
        }

        /// <summary>Attempts to get the value of the given key</summary>
        /// <param name="key">Key to get</param>
        /// <param name="value">Value of the key</param>
        /// <returns>Returns true in case the key has been found</returns>
        public override bool TryGet(string key, out string value)
        {
            if (!base.TryGet(key, out value)) { return false; }
            else if (!this.encryptedKeys.Contains(key)) { return true; }

            //Key is encrypted and must therefore be decrypted in order to return.
            //Note that the decoded base-64 bytes contains the encrypted prefix which must be excluded when unprotection
            var protectedValueWithPrefix = Convert.FromBase64String(value);
            var protectedValue = new byte[protectedValueWithPrefix.Length - encryptedPrefixBytes.Length];
            Buffer.BlockCopy(protectedValueWithPrefix, encryptedPrefixBytes.Length, protectedValue, 0, protectedValue.Length);

            //var unprotectedValue = ProtectedData.Unprotect(protectedValue, this.protectedSource.Entropy, this.protectedSource.Scope);
            var unprotectedValue = StringCipher.Decrypt(protectedValue, protectedSource.Password);
            value = unprotectedValue;
            return true;
        }
    }
}
