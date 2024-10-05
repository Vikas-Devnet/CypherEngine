namespace CypherEngine
{
    public class CypherSuite
    {
        public static bool EncryptText(string Plaintext, string Byte32SecretKey, string Byte16IV, out string CypherText, out string ErrorMessage)
        {
            CypherText = string.Empty; ErrorMessage = string.Empty;
            try
            {
                CypherText = CypherUtility.GetEncryptedText(Plaintext, Byte32SecretKey, Byte16IV);
                return true;
            }
            catch (Exception e)
            {
                ErrorMessage = e.ToString();
                return false;
            }

        }
        public static bool DecryptText(string CypherText, string Byte32SecretKey, string Byte16IV, out string Plaintext, out string ErrorMessage)
        {
            Plaintext = string.Empty; ErrorMessage = string.Empty;
            try
            {
                Plaintext = CypherUtility.GetDecryptedText(CypherText, Byte32SecretKey, Byte16IV);
                return true;
            }
            catch (Exception e)
            {
                ErrorMessage = e.ToString();
                return false;
            }
        }

        public static bool GenerateSecretKeyAndIV(out string byte32SecretKey, out string byte16IV, out string ErrorMessage)
        {
            byte32SecretKey = string.Empty; byte16IV = string.Empty; ErrorMessage = string.Empty;
            try
            {
                CypherUtility.GenerateKeyAndIV(out byte32SecretKey, out byte16IV);
                return true;
            }
            catch (Exception e)
            {
                ErrorMessage = e.ToString();
                return false;
            }
        }

    }
}

