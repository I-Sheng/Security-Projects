using System;
using System.Text;
using System.Security.Cryptography;

namespace padding_oracle
{
    class EncryptString
    {
        public EncryptString()
        {
            key = RandomNumberGenerator.GetBytes(32);
            verbose = false;
        }

        byte[] key;
        bool verbose;
        
        public bool TryDecrypt(byte[] enc_data)
        {
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            byte[] iv = new byte[aes.IV.Length];
            Array.Copy(enc_data, iv, iv.Length);
            byte[] enc_msg = new byte[enc_data.Length - iv.Length];
            Array.Copy(enc_data, iv.Length, enc_msg, 0, enc_msg.Length);
            MemoryStream ms = new MemoryStream(enc_msg);

            try
            {
                using (CryptoStream cryptoStream = new(ms, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read))
                {
                    using (StreamReader reader = new StreamReader(cryptoStream))
                    {
                        string msg = reader.ReadToEnd();
                        if(verbose)
                            Console.WriteLine("Decrypted Message = success");
                        return true;
                    }
                }

            }
            catch(Exception ex)
            {
                if(verbose)
                    Console.WriteLine("Failed to decrypt " + ex.Message);
            }
            return false;
        }

        public byte[] Encrypt(string s)
        {
            byte[] iv = RandomNumberGenerator.GetBytes(16);
            // Convert the string to bytes
            byte[] s_bytes = Encoding.ASCII.GetBytes(s);

            // Have to do some extra to get around .NET being helpful
            // Pad using PKCS7 manually
            byte[] bytes_to_encrypt = new byte[(s_bytes.Length/16 + 1) * 16];
            Array.Copy(s_bytes, bytes_to_encrypt, s_bytes.Length);
            int padding_bytes = bytes_to_encrypt.Length - s_bytes.Length;

            for(int i = s_bytes.Length; i < bytes_to_encrypt.Length; ++i)
            {
                bytes_to_encrypt[i] = (byte)padding_bytes;
            }

            using(MemoryStream ms = new MemoryStream())
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Padding = PaddingMode.None;

                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        ms.Write(iv, 0, iv.Length);

                        using (BinaryWriter encryptWriter = new(cs))
                        {
                            encryptWriter.Write(bytes_to_encrypt, 0, bytes_to_encrypt.Length);
                        }
                    }
                }

                ms.Close();
                return ms.ToArray();
            }
        }

    }

    class oracle_demo
    {

        static void Main(string[] args)
        {
            if(args.Length == 0)
            {
                Console.WriteLine("Enter string to be encrypted");
                return;
            }

            EncryptString enc = new EncryptString();
            byte[] enc_bytes = enc.Encrypt(args[0]);

            // Test to make sure it works
            if (enc.TryDecrypt(enc_bytes))
                Console.WriteLine("Ready to attempt padding oracle");

            // Now find how long the string actually is
            byte[] test = new byte[enc_bytes.Length];
            Array.Copy(enc_bytes, test, test.Length);
            int offset = test.Length - 16;
            int bytes_padding = 0;

            for (int i = offset; i < test.Length; i++)
            {
                test[i] = ++test[i];

                if(!enc.TryDecrypt(test))
                {
                    Console.WriteLine("Padding found at offset " + i);
                    bytes_padding = enc_bytes.Length - i;
                    break;
                }
            }

            // Now let's try tampering with the previous block
            Array.Copy(enc_bytes, test, test.Length);
            offset = test.Length - 17;
            int original_value = test[offset];
            int cipherPrime = 0;
            byte[] clear_text= new byte[16];

            while(enc_bytes.Length > 16)
            {
                for (int padding_value = 1; padding_value < 17; ++padding_value)
                {
                    bool found = false;
                    for (int i = 0; i < 256; ++i)
                    {
                        if (i == original_value)
                            continue;

                        test[offset] = (byte)i;
                        if (enc.TryDecrypt(test))
                        {
                            // Padding is correct
                            // Check whether it was by accident
                            // Tampering with previous byte
                            // should have no effect
                            if(offset > 0)
                            {
                                test[offset - 1] = (byte)(test[offset - 1] + 1);
                                if (!enc.TryDecrypt(test))
                                {
                                    // It was by accident
                                    continue;
                                }
                            }

                            cipherPrime = i;
                            clear_text[16 - padding_value] = (byte)((cipherPrime ^ padding_value) ^ enc_bytes[offset]);
                            found = true;
                            if (clear_text[16 - padding_value] < ' ')
                            {
                                Console.WriteLine("Decrypted value = " + clear_text[16 - padding_value]);
                            }
                            else
                            {
                                Console.WriteLine("Decrypted value = " + (char)clear_text[16 - padding_value]);
                            }
                            break;
                        }
                    }

                    if (!found)
                    {
                        Console.WriteLine("Decryption failed, buggy code");
                        return;
                    }

                    // Set up for the next try
                    for (int j = 1; j < padding_value + 1; ++j)
                    {
                        int index = test.Length - (16 + j);
                        test[index] = (byte)((padding_value + 1) ^ enc_bytes[index] ^ clear_text[16 - j]);
                    }
                    offset--;
                }

                Array.Resize(ref enc_bytes, enc_bytes.Length - 16);
                Array.Resize(ref test, test.Length - 16);

                Array.Copy(enc_bytes, test, test.Length);

            }


        }
    }
}
