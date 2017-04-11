// mcs encode.cs && mono encode.exe ../_shared/payload.json sealed.json

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Unsealed
{
    class Secrets
    {
        static void Main(string[] args) {
            if (args.Length != 2) {
                Console.WriteLine("./encode.exe payload.json sealed.json");
                System.Environment.Exit(1);
            }

            var path = String.Format("{0}/../_shared/public_certificate.der", AppDomain.CurrentDomain.BaseDirectory);
            X509Certificate cert = X509Certificate.CreateFromCertFile(path);
            X509Certificate2 certificate = new X509Certificate2(cert);

            var random = Guid.NewGuid().ToString("n").ToCharArray();
            var salt = new byte[16];
            for (int i = 0; i != salt.Length; i++)
                salt[i] = (byte)random[i];

            RSACryptoServiceProvider rsa = certificate.PublicKey.Key as RSACryptoServiceProvider;
            var token = rsa.Encrypt(salt, false);

            var data = File.ReadAllBytes(args[0]);
            RC4(ref data, salt);

            var json = String.Format("{{\"token\":\"{0}\", \"payload\":\"{1}\"}}", Convert.ToBase64String(token), Convert.ToBase64String(data));
            File.WriteAllText(args[1], json);
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
