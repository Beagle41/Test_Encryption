using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace Test_Encryption
{
    class Program
    {
        /*
         * This size of the IV (in bytes) must = (keysize / 8).  Default keysize is 256, so the IV must be 32 bytes long.  
         * Using a 16 character string here gives us 32 bytes when converted to a byte array.
         */
        private const string initVector = "pemgail9uzpgzl88";
        private const int keysize = 256;     // This constant is used to determine the keysize of the encryption algorithm
        public static string InitVector => initVector;
        public static int Keysize => keysize;

        public static class Encrypt
        {

            public static bool EncryptString(string PlainText, string PassPhrase, out string EncryptedText, out string ErrorText)
            {
                if (string.IsNullOrEmpty(PlainText) || string.IsNullOrEmpty(PassPhrase))
                {
                    ErrorText = "Inputs cannot be null or empty";
                    EncryptedText = string.Empty;
                    return false;
                }

                byte[] plainTextBytes = Encoding.UTF8.GetBytes(PlainText);
                byte[] initVectorBytes = Encoding.UTF8.GetBytes(InitVector);

                PasswordDeriveBytes password = new PasswordDeriveBytes(PassPhrase, null);
                byte[] keyBytes = password.GetBytes(Keysize / 8);
                RijndaelManaged symmetricKey = new RijndaelManaged();
                symmetricKey.Mode = CipherMode.CBC;
                ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);
                MemoryStream memoryStream = new MemoryStream();
                CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                cryptoStream.FlushFinalBlock();
                byte[] cipherTextBytes = memoryStream.ToArray();
                memoryStream.Close();
                cryptoStream.Close();

                EncryptedText =  Convert.ToBase64String(cipherTextBytes);
                ErrorText = string.Empty;

                return true;

            }
            public static string DecryptString(string cipherText, string passPhrase)
            {
                byte[] initVectorBytes = Encoding.UTF8.GetBytes(InitVector);
                byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

                PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, null);
                byte[] keyBytes = password.GetBytes(Keysize / 8);
                RijndaelManaged symmetricKey = new RijndaelManaged();
                symmetricKey.Mode = CipherMode.CBC;
                ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
                MemoryStream memoryStream = new MemoryStream(cipherTextBytes);
                CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                byte[] plainTextBytes = new byte[cipherTextBytes.Length];
                int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                memoryStream.Close();
                cryptoStream.Close();

                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
            }

        }

        private static void Main(string[] args)
        {
            string inputString;
            string encryptedString = string.Empty;
            string errorMessage = string.Empty;

            Console.Write("Enter String to encrypt: ");
            inputString = Console.ReadLine();
            if (Encrypt.EncryptString(inputString, "SalesLogix", out encryptedString, out errorMessage))
            {
                Console.WriteLine("Encrypted string: {0}",  encryptedString);
                Console.WriteLine("Decrypted string: {0}", Encrypt.DecryptString(encryptedString, "SalesLogix"));
            }
            else
            {
                Console.WriteLine("Error message: {0}. Input: {1}", errorMessage, inputString);
            }

            Console.Write("Press any key to exit. ");
            Console.Read();
        }
    }
}
