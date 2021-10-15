# CipherLib
A quick way to encrypt specific fields in appsettings.json for .NET Core

In fact, this refers to the practice on the Internet and makes some modifications to make it easier to use on .NET Core, and has not done a complete security assessment. Sometimes security and convenience are mutually exclusive, please choose the best a way that suits your convenience and part of the security.

Which article to refer to has also been commented in the code.

 ## Getting Started

Assuming your appsettings.json is as follows
```json
{
    "SomeApi": {
        "EndPoint": "https://fakeapi.com/resource",
        "Secret": "yourSecret"
    },
    "SomeOtherSetting": "Some text that doesn't need to be encrypted",
    "DBConnection": "Server=YourSQLServer;Database=YourDB;Persist Security Info=True;User ID=YourUser;Password=YourPassword;"
}
```
And you originally used AddJsonFile
```C#
new ConfigurationBuilder().AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
```
Now, use CipherLib
```C#
using CipherLib.Extensions;
```
Since a password is used for symmetric encryption, please use a safe way to obtain your password.
```C#
var password = GetPasswordFromEnvironmentVariable();
//or
var password = GetPasswordFromFile();
//or
var password = GetPasswordFromSomewhere();
```
Use AddProtectedJsonFile instead of AddJsonFile, and please add regular expressions to indicate which fields need to be encrypted.
```C#
new ConfigurationBuilder()
.AddProtectedJsonFile(
    password,
    "appsettings.json", 
    optional: false,
    reloadOnChange: true, 
    new Regex("SomeApi:Secret"), 
    new Regex("DBConnection"))
```
Build your program. If the fields in your appsettings.json have not been encrypted, the fields in the build folder will be encrypted. If the fields have been encrypted, they will not be encrypted again.

You can view the example in the TestExample project