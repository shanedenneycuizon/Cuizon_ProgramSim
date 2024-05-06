using System;
using System.Security.Cryptography;
using System.Text;

public class Program
{
    static int p = 199;
    static int g = 127;
    static int private_A = 57;
    static int private_B = 167;

    // Original message
    static string message = "The Mandalorian Must Always Recite, This is The Way!";

    static void Main(string[] args)
    {
        int public_A = ModPow(g, private_A, p);
        int public_B = ModPow(g, private_B, p);

        int shared_key_A = ModPow(public_B, private_A, p);
        int shared_key_B = ModPow(public_A, private_B, p);

        string key_A = TransformKey(shared_key_A);
        string key_B = TransformKey(shared_key_B);

        string[] sub_messages = ChunkString(message, 16);

        // Encrypt each sub-message
        string[] encrypted_messages = new string[sub_messages.Length];
        for (int i = 0; i < sub_messages.Length; i++)
        {
            encrypted_messages[i] = Encrypt(key_A, sub_messages[i]);
        }

        // Decrypt each sub-message
        string[] decrypted_messages = new string[encrypted_messages.Length];
        for (int i = 0; i < encrypted_messages.Length; i++)
        {
            decrypted_messages[i] = Decrypt(key_B, encrypted_messages[i]);
        }

        // Reconstruct the original message
        string reconstructed_message = string.Join("", decrypted_messages);

        // Output
        Console.WriteLine("MESSAGE: " + message);
        for (int i = 0; i < sub_messages.Length; i++)
        {
            Console.WriteLine("Sub-message" + (i + 1) + ": \"" + sub_messages[i] + "\" - [" + ByteArrayToString(Encoding.ASCII.GetBytes(sub_messages[i])) + "]");
        }
    }

    // Modular exponentiation function
    static int ModPow(int baseNum, int exponent, int modulus)
    {
        int result = 1;
        while (exponent > 0)
        {
            if (exponent % 2 == 1)
                result = (result * baseNum) % modulus;
            exponent >>= 1;
            baseNum = (baseNum * baseNum) % modulus;
        }
        return result;
    }

    // Transform shared key into 128-bit key
    static string TransformKey(int sharedKey)
    {
        string sharedKeyHex = sharedKey.ToString("X");
        StringBuilder transformedKey = new StringBuilder();
        switch (sharedKeyHex.Length)
        {
            case 1:
                transformedKey.Append((sharedKeyHex + "C").PadRight(32, 'C'));
                break;
            case 2:
                transformedKey.Append((sharedKeyHex + "DD").PadRight(32, 'D'));
                break;
            case 3:
                transformedKey.Append((sharedKeyHex + "F").PadRight(32, 'F'));
                break;
        }
        return transformedKey.ToString();
    }

    // Turn original message into sub-messages
    static string[] ChunkString(string str, int chunkSize)
    {
        int numChunks = (int)Math.Ceiling((double)str.Length / chunkSize);
        string[] chunks = new string[numChunks];
        for (int i = 0; i < numChunks; i++)
        {
            int length = Math.Min(chunkSize, str.Length - i * chunkSize);
            chunks[i] = str.Substring(i * chunkSize, length).PadRight(chunkSize, '@');
        }
        return chunks;
    }

    // Encrypt function
    static string Encrypt(string key, string plaintext)
    {
        byte[] keyBytes = Encoding.ASCII.GetBytes(key);
        byte[] plaintextBytes = Encoding.ASCII.GetBytes(plaintext);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = keyBytes;
            aesAlg.Mode = CipherMode.ECB;
            aesAlg.Padding = PaddingMode.None;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            byte[] encryptedBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

            return ByteArrayToString(encryptedBytes);
        }
    }

    // Decrypt function
    static string Decrypt(string key, string ciphertext)
    {
        byte[] keyBytes = Encoding.ASCII.GetBytes(key);
        byte[] encryptedBytes = StringToByteArray(ciphertext);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = keyBytes;
            aesAlg.Mode = CipherMode.ECB;
            aesAlg.Padding = PaddingMode.None;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

            return Encoding.ASCII.GetString(decryptedBytes);
        }
    }

    static string ByteArrayToString(byte[] byteArray)
    {
        StringBuilder hex = new StringBuilder(byteArray.Length * 2);
        foreach (byte b in byteArray)
            hex.AppendFormat("{0:x2} ", b);
        return hex.ToString().ToUpper();
    }

    static byte[] StringToByteArray(string hex)
    {
        hex = hex.Replace(" ", "");
        byte[] byteArray = new byte[hex.Length / 2];
        for (int i = 0; i < byteArray.Length; i++)
            byteArray[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return byteArray;
    }
}
