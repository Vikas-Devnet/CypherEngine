using System.Security.Cryptography;

namespace CypherEngine
{
    internal class CypherUtility
    {
        internal static string GetEncryptedText(string plainText, string byte32SecretKey, string byte16IV)
        {
            try
            {
                string intermediateText = ReverseString(plainText);
                intermediateText = SubstituteText(intermediateText, byte16IV.Length / 6);
                intermediateText = AesOperations(intermediateText, byte32SecretKey, byte16IV, true);
                return intermediateText;
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }
        internal static string GetDecryptedText(string cypherText, string byte32SecretKey, string byte16IV)
        {
            try
            {
                string intermediateText = AesOperations(cypherText, byte32SecretKey, byte16IV, false);
                intermediateText = InverseSubstitute(intermediateText, byte16IV.Length / 6);
                intermediateText = ReverseString(intermediateText);
                return intermediateText;
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }
        internal static void GenerateKeyAndIV(out string byte32SecretKey, out string byte16IV)
        {
            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();
            aes.GenerateIV();

            byte32SecretKey = Convert.ToBase64String(aes.Key);
            byte16IV = Convert.ToBase64String(aes.IV);
        }
        private static string AesOperations(string input, string byte32SecretKey, string byte16IV, bool isEncrypt)
        {
            if (string.IsNullOrEmpty(input)) throw new ArgumentNullException(nameof(input));
            byte[] keyBytes = Convert.FromBase64String(byte32SecretKey);
            byte[] ivBytes = Convert.FromBase64String(byte16IV);
            if (keyBytes == null || keyBytes.Length != 32) throw new ArgumentException("Secret Key (Byte32SecretKey) must be 32 bytes long for AES-256.");
            if (ivBytes == null || ivBytes.Length != 16) throw new ArgumentException("Initialisation Vector (Byte16IV) must be 16 bytes long.");

            using Aes aesAlg = Aes.Create();
            aesAlg.Key = keyBytes;
            aesAlg.IV = ivBytes; //IV = Initialisation Vector 
            ICryptoTransform cryptoTransform = isEncrypt
                ? aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV)
                : aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using MemoryStream ms = new();
            using CryptoStream cs = new(ms, cryptoTransform, CryptoStreamMode.Write);
            if (isEncrypt)
            {
                using (StreamWriter sw = new(cs))
                {
                    sw.Write(input);
                }
                return Convert.ToBase64String(ms.ToArray());
            }
            else
            {
                byte[] inputBytes = Convert.FromBase64String(input);
                cs.Write(inputBytes, 0, inputBytes.Length);
                cs.FlushFinalBlock();
                ms.Position = 0;
                using StreamReader sr = new(ms);
                return sr.ReadToEnd();
            }
        }
        private static string ReverseString(string inputText)
        {
            ArgumentNullException.ThrowIfNull(inputText);
            char[] charArray = inputText.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }
        private static string SubstituteText(string input, int key)
        {
            char[] buffer = input.ToCharArray();

            for (int i = 0; i < buffer.Length; i++)
            {
                char letter = buffer[i];
                if (char.IsUpper(letter))
                {
                    letter = (char)(((letter - 'A' + key) % 26) + 'A');
                }
                else if (char.IsLower(letter))
                {
                    letter = (char)(((letter - 'a' + key) % 26) + 'a');
                }
                buffer[i] = letter;
            }

            return new string(buffer);
        }

        private static string InverseSubstitute(string substitutedText, int key)
        {
            return SubstituteText(substitutedText, 26 - key);
        }
    }
}
