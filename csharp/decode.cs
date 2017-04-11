// mcs /reference:System.Web.Extensions.dll decode.cs && mono decode.exe sealed.json

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web.Script.Serialization;

namespace Unsealed
{
    class Secrets
    {
        static void Main(string[] args) {
            if (args.Length != 1) {
                Console.WriteLine("./decode.exe sealed.json");
                System.Environment.Exit(1);
            }

            var path = String.Format("{0}/../_shared/private_p12.p12", AppDomain.CurrentDomain.BaseDirectory);
            X509Certificate2 certificate = new X509Certificate2(path, "", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            var data = File.ReadAllBytes(args[0]);
            var jsonString = Encoding.UTF8.GetString(data);

            var serializer = new JavaScriptSerializer();
            Dictionary<string, object> json = (Dictionary<string, object>)serializer.DeserializeObject(jsonString);
            var token = json["token"] as String;
            var payload = json["payload"] as String;

            RSACryptoServiceProvider rsa = certificate.PrivateKey as RSACryptoServiceProvider;
            var salt = rsa.Decrypt(Convert.FromBase64String(token), false);

            var p = Convert.FromBase64String(payload);
            RC4(ref p, salt);

            Console.WriteLine("unsealed:");
            Console.WriteLine("{0}", Encoding.UTF8.GetString(p));
        }

        static void RC4(ref Byte[] bytes, Byte[] key) // identicial in both encode/decode
        {
            Byte[] s = new Byte[256];
            Byte[] k = new Byte[256];
            Byte temp;
            int i, j;

            for (i = 0; i < 256; i++)
            {
                s[i] = (Byte)i;
                k[i] = key[i % key.GetLength(0)];
            }

            j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + s[i] + k[i]) % 256;
                temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }

            i = j = 0;
            for (int x = 0; x < bytes.GetLength(0); x++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                temp = s[i];
                s[i] = s[j];
                s[j] = temp;
                int t = (s[i] + s[j]) % 256;
                bytes[x] ^= s[t];
            }
        }
    }
}
