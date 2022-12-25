using epicor.bll;
using epicor.entities;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security;
using System.Threading.Tasks;
using Microsoft.VisualBasic;
//using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
//using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using epicor.entities;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;

namespace epicor.api
{
    public class Authenticate
    {
        //string xmlFilePath = HttpContext.Current.Server.MapPath("~/Config/Config.xml");
        public static User user = new User();
         public LoginResponse AuthenticateUser(LoginRequest loginrequest,IConfiguration configuration)
       // public async Task<ActionResult<User>> AuthenticateUser(LoginRequest loginrequest)
        {
            try
            {
                LoginResponse loginResponse = new LoginResponse();
                //UnicodeEncoding ByteConverter = new UnicodeEncoding();
                //RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                CreatePasswordHash(loginrequest.Password,out byte[] passwordHash, out byte[] passwordSalt);
               // string decryptedPassword = "";
                //LoginRequest loginrequest = new LoginRequest();
                user.Username = loginrequest.Username;
                user.PasswordHash = passwordHash;//decryptedPassword.Replace("\0", "");
                user.PasswordSalt= passwordSalt;

                HttpResponseMessage responseMsg = new HttpResponseMessage();

                int secureDomainId = UserManager.ValidateUser(loginrequest.Username, loginrequest.Password);

                if (secureDomainId == -1)
                {
                    return null;
                }
                else
                {
                    string token = CreateToken(user,configuration);
                    loginResponse.Token = token;
                    return loginResponse;
                }
            }
            catch (Exception ex)
            {
               // Log4NetHelper.LogError(null, ex.ToString());
                return null;
            }
        }

        private string CreateToken(User user, IConfiguration configuration)
        {

            List<Claim> claims = new List<Claim>
            {
            new Claim(ClaimTypes.Name, user.Username)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                configuration.GetSection("AppSettings:Token").Value));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims:claims,
                expires:DateTime.Now.AddDays(1),
                signingCredentials:creds);
            var jwt=new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        public int GetUserByUserName(string userName, string password)
        {
            try
            {
                return UserManager.ValidateUser(userName, password);
            }
            catch (Exception ex)
            {
               // Log4NetHelper.LogError(null/* TODO Change to default(_) if this is not a reference type */, ex.ToString());
                return -1;
            }
        }

        //private string CreateToken(string username, bool rememberMe = true)
        //{
        //    try
        //    {
        //        string issuer = ConfigManager.GetIssuer();
        //        string audience = ConfigManager.GetAudience();
        //        int tokenExpiryTime = ConfigManager.GetTokenExpiryTime();
        //        int rememberMeTime = ConfigManager.GetRememberMeTime();
        //        // Dim issuer = ConfigManager.GetIssuer()
        //        // Dim audience = ConfigManager.GetAudience()
        //        DateTime issuedAt = DateTime.UtcNow;
        //        DateTime expires = DateTime.UtcNow.AddMinutes(tokenExpiryTime);
        //        if ((rememberMe.Equals(true)))
        //            expires = DateTime.UtcNow.AddDays(rememberMeTime);
        //        var tokenHandler = new JwtSecurityTokenHandler();
        //        List<Claim> claims = new List<Claim>();
        //        claims.Add(new Claim(ClaimTypes.Name, username));
        //        ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims);
        //        //ClaimsIdentity claimsIdentity = new ClaimsIdentity(
        //        //{
        //        //    new Claim(ClaimTypes.Name, username)
        //        //});
        //        var sec = ConfigManager.GetSec();
        //        // Const sec As String = "401b09eab3c013d4ca54922bb802bec8fd5318192b0a75f201d8b3727429090fb337591abd3e44453b954555b7a0812e1081c39b740293f765eae731f5a65ed1"
        //        var now = DateTime.UtcNow;
        //        var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(sec));
        //        var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature);
        //        var token = (JwtSecurityToken)tokenHandler.CreateJwtSecurityToken(issuer: issuer, audience: audience, subject: claimsIdentity, notBefore: issuedAt, expires: expires, signingCredentials: signingCredentials);
        //        var tokenString = tokenHandler.WriteToken(token);
        //        return tokenString;
        //    }
        //    catch (Exception ex)
        //    {
        //        Log4NetHelper.LogError(null/* TODO Change to default(_) if this is not a reference type */, ex.ToString());
        //        return null;
        //    }
        //}


        //public static string ValidateToken(string token)
        //{
        //    try
        //    {
        //        string username = null;
        //        ClaimsPrincipal principal = GetPrincipal(token);
        //        if (principal == null)
        //            return null;
        //        ClaimsIdentity identity = null;

        //        try
        //        {
        //            identity = (ClaimsIdentity)principal.Identity;
        //        }
        //        catch (NullReferenceException __unusedNullReferenceException1__)
        //        {
        //            return null;
        //        }

        //        Claim usernameClaim = identity.FindFirst(ClaimTypes.Name);
        //        username = usernameClaim.Value;
        //        return username;
        //    }
        //    catch (Exception ex)
        //    {
        //        Log4NetHelper.LogError(null/* TODO Change to default(_) if this is not a reference type */, ex.ToString());
        //        return null;
        //    }
        //}

        //public static ClaimsPrincipal GetPrincipal(string token)
        //{
        //    try
        //    {
        //        var issuer = ConfigManager.GetIssuer();
        //        var audience = ConfigManager.GetAudience();
        //        var sec = ConfigManager.GetSec();
        //        var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(sec));
        //        string Secret = "ERMN05OPLoDvbTTa/QkqLNMI7cPLguaRyHzyg7n5qNBVjQmtBhz4SzYh4NBVCXi3KJHlSXKP+oi2+bXr6CUYTR==";
        //        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
        //        JwtSecurityToken jwtToken = (JwtSecurityToken)tokenHandler.ReadToken(token);
        //        if (jwtToken == null)
        //            return null;
        //        byte[] key = Convert.FromBase64String(Secret);
        //        TokenValidationParameters parameters = new TokenValidationParameters()
        //        {
        //            RequireExpirationTime = true,
        //            ValidIssuer = audience,
        //            ValidAudience = issuer,
        //            IssuerSigningKey = securityKey,
        //            ValidateLifetime = true,
        //            ValidateIssuerSigningKey = true
        //        };

        //        Microsoft.IdentityModel.Tokens.SecurityToken securityToken;
        //        ClaimsPrincipal principal = tokenHandler.ValidateToken(token, parameters, out securityToken);
        //        return principal;
        //    }
        //    catch (Exception ex)
        //    {
        //       // Log4NetHelper.LogError(null/* TODO Change to default(_) if this is not a reference type */, ex.ToString());
        //        return null;
        //    }
        //}

        //public static byte[] Decryption(byte[] Data, bool DoOAEPPadding)
        //{
        //    try
        //    {
        //        byte[] decryptedData;
        //        RSACryptoServiceProvider RSANew = new RSACryptoServiceProvider();
        //        RSANew.FromXmlString(ReadAuthenticationXML());
        //        decryptedData = RSANew.Decrypt(Data, DoOAEPPadding);
        //        return decryptedData;
        //    }
        //    catch (Exception ex)
        //    {
        //       // Log4NetHelper.LogError(null/* TODO Change to default(_) if this is not a reference type */, ex.ToString());
        //        return null;
        //    }
        //}


        //public byte[] Encryption(string password, bool DoOAEPPadding)
        //{
        //    try
        //    {
        //        //string publicKey = "<RSAKeyValue><Modulus>sisuTlXP9T7TKdOKDh281SvMHJ7LP16cUFRHvMlZ7Q9R70MfwHSvsw3GgLYOL11LfVt1GkyWz5XFoOZzc/lYvfv/DK/vfCErailqUBzPsbcHG7kvVQsjg9MIGWzFgE/TCDlGRDAWhYsgrAoxY8YxA+cspX4CaM1D2TH78kPE3Fk=</Modulus><Exponent>AQAB</Exponent><P>6zfkuuZCLqb/bMUUsm+mdG7xiwLM98cdh/qqF57yzCcQq/BAVr4+XADjQBNSVmjj71GlREB/xCmQMMkXPrp+Rw==</P><Q>wej0BUz9y1hi3dYnVgaqeJcgcuvSFg9mGGxEdnXpCiOMZU+7hTOHasfQk5XRjDF8TBQkVZAmnSNFGSWSlvAAXw==</Q><DP>tU2Q1Wr0Kmd4TAugx2T95ZM6RQ70lCv7HDve7XQL68ZUuGLoBLSA9oOMpm/+MDKLNoU1IOWiVb4/sQrfCu/Osw==</DP><DQ>Hf2BgDBgMEsDP3wXqV5ujygQhLWkUHUhPTXBgPDLkh3dYO3r+rX1g7ZTs/+/4QbmSn3zAKjC0BrcXP9KpL2J0Q==</DQ><InverseQ>lFnmwOXxnUf4g9v8fnmi4ZQ780UdQSgjfe1wc7RYiYMkhpJCgpzLAUofMNpowix+tZAADEfrrBjiVEowXatlHw==</InverseQ><D>N9e66siQpqBrVPe9lJETh4jzr6DBuXnw6miQF4bQjbG4j5JtWEf6bdeKePsW1Rebuo241WZd+nBKAhVY6GelvVfG42ZnjD8G2Oyn4PZD0UdfLeqn7KKYyNAVnbcwjEyfSl7AIVlmL0jd/akx6TxvEZucd309b1+hi3Lm/uWrk+U=</D></RSAKeyValue>";
        //        UnicodeEncoding ByteConverter = new UnicodeEncoding();
        //        byte[] byteArray = ByteConverter.GetBytes(password);// Encoding.Unicode.GetBytes(password);// Encoding.ASCII.GetBytes(password);
        //        using (RSACryptoServiceProvider RSANew = new RSACryptoServiceProvider())
        //        {
        //            RSANew.FromXmlString(ReadAuthenticationXML()); // publicKey;
        //            byte[] encryptedBytes = RSANew.Encrypt(byteArray, DoOAEPPadding);
        //            return encryptedBytes;
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //       // Log4NetHelper.LogError(null/* TODO Change to default(_) if this is not a reference type */, ex.ToString());
        //        return null;
        //    }
        //}

        //public byte[] Encryption(string password, bool DoOAEPPadding)
        //{
        //    try
        //    {
        //        UnicodeEncoding ByteConverter = new UnicodeEncoding();
        //        byte[] Data = Encoding.Unicode.GetBytes(password);// Encoding.ASCII.GetBytes(password);
        //        byte[] decryptedData;
        //        RSACryptoServiceProvider RSANew = new RSACryptoServiceProvider();
        //        RSANew.FromXmlString(ReadAuthenticationXML());
        //        decryptedData = RSANew.Encrypt(Data, DoOAEPPadding);
        //        return decryptedData;
        //    }
        //    catch (Exception ex)
        //    {
        //        Log4NetHelper.LogError(null/* TODO Change to default(_) if this is not a reference type */, ex.ToString());
        //        return null;
        //    }
        //}

        //public static string ReadAuthenticationXML()
        //{
        //    string xmlFilePath = HttpContext.Current.Server.MapPath("~/Config/Config.xml");
        //    string contents = "";
        //    XmlDocument doc = new XmlDocument();
        //    using (StreamReader streamReader = new StreamReader(xmlFilePath, Encoding.UTF8))
        //    {
        //        contents = streamReader.ReadToEnd();
        //    }
        //    doc.LoadXml(contents);
        //    return doc.InnerXml;
        //}

        //public static string HashPassword(string password)
        //{
        //    try
        //    {
        //        string salt = ConfigManager.GetSaltForHash();
        //        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(password + salt);
        //        System.Security.Cryptography.SHA256Managed sha256hashstring = new System.Security.Cryptography.SHA256Managed();
        //        byte[] hash = sha256hashstring.ComputeHash(bytes);
        //        return Convert.ToBase64String(hash);
        //    }
        //    catch (Exception ex)
        //    {
        //       // Log4NetHelper.LogError(null/* TODO Change to default(_) if this is not a reference type */, ex.ToString());
        //        return null;
        //    }
        //}

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computeHash.SequenceEqual(passwordHash);
            }
        }
    }
}
