/**
 * TripleDESCBC-Decryption Project
 * Author: Leo Angelo Genota
 * **/
using System.Security.Cryptography;
using System.Text;

namespace TripleDESDecryption
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Pre-defined values for decryption
            string ciphertext = "{HEX_FORMAT_CIPHERTEXT}";
            string secretKey = "{HEX_FORMAT_SECRET_KEY}";
            string iv = "{HEX_FORMAT_IV}";

            // Convert the secret key and IV strings to byte arrays
            byte[] convertedSecretKey = ConvertToByteArray(secretKey);
            byte[] convertedIv = ConvertToByteArray(iv);
            byte[] convertedCiphertext = ConvertToByteArray(ciphertext);

            // Create the TripleDES object
            TripleDES tripleDES = GenerateTripleDESObject(convertedSecretKey, convertedIv);

            // Create the decryptor
            ICryptoTransform decryptor = tripleDES.CreateDecryptor();

            // Decrypt the converted ciphertext value
            byte[] decryptedBytes = decryptor.TransformFinalBlock(convertedCiphertext, 0, convertedCiphertext.Length);

            Console.WriteLine("Decrypted plaintext: " + Encoding.UTF8.GetString(decryptedBytes));
        }

        /**
         * Creates a TripleDES object based on the input key and initialization vector
         * **/
        private static TripleDES GenerateTripleDESObject(byte[] Key, byte[] IV)
        {
            TripleDES tripleDES = TripleDES.Create();
            tripleDES.Key = Key;
            tripleDES.IV = IV;
            tripleDES.Mode = CipherMode.CBC;
            tripleDES.Padding = PaddingMode.PKCS7;

            return tripleDES;
        }

        /**
         * Converts a hex string to a byte array
         * **/
        private static byte[] ConvertToByteArray(string hexString)
        {
            int length = hexString.Length;
            byte[] result = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                result[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return result;
        }
    }
}