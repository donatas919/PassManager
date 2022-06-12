using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace PassManager
{
    internal class Program
    {
        private static Random random = new Random();

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        public static String CreateHash(string input)
        {
            byte[] salt;
            new RNGCryptoServiceProvider().GetBytes(salt = new byte[16]);
            
            var pbkdf2 = new Rfc2898DeriveBytes(input, salt, 100000);
            byte[] hash = pbkdf2.GetBytes(20);
            
            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);
            
            string savedPasswordHash = Convert.ToBase64String(hashBytes);
            return savedPasswordHash;
        }

        public static string Encrypt(string plainText)
        {
            byte[] src = Encoding.UTF8.GetBytes(plainText);
            byte[] key = Encoding.ASCII.GetBytes("770A8A65DA156D24EE2A093277530142");
            RijndaelManaged aes = new RijndaelManaged();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = 128;
        
            using (ICryptoTransform encrypt = aes.CreateEncryptor(key, null))
            {
                byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);
                encrypt.Dispose();
                return Convert.ToBase64String(dest);
            }
        }
        
        public static string Decrypt(string plainText)
        {
            byte[] src = Convert.FromBase64String(plainText);
            byte[] key = Encoding.ASCII.GetBytes("770A8A65DA156D24EE2A093277530142");
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = 128;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.ECB;
            using (ICryptoTransform decrypt = aes.CreateDecryptor(key, null))
            {
                byte[] dest = decrypt.TransformFinalBlock(src, 0, src.Length);
                decrypt.Dispose();
                return Encoding.UTF8.GetString(dest);
            }
        }

        [STAThread]
        public static void Main(string[] args)
        {
            //Login/Register options
            Console.WriteLine("1. Login");
            Console.WriteLine("2. Register");
            Console.WriteLine("3. Exit");

            int x = Convert.ToInt32(Console.ReadLine());

            String masterLogin;
            
            switch (x)
            {
                //Login case
                case 1:
                    Console.WriteLine();
                    Console.WriteLine("Enter login");
                    String loginLogin = Console.ReadLine();
                    Console.WriteLine("Enter password");
                    String loginPassword = Console.ReadLine();
                    
                    String login;
                    String password;
                    try
                    {
                        using (StreamReader readText = new StreamReader($"{loginLogin}.txt"))
                        {
                            login = readText.ReadLine();
                            password = readText.ReadLine();
                            //writeText.Close();
                        }
                    }
                    catch (FileNotFoundException e)
                    {
                        Console.WriteLine("there is no such user");
                        Console.WriteLine();
                        Console.WriteLine(e);
                        throw;
                    }
                    
                    //Extract the bytes
                    byte[] hashBytes = Convert.FromBase64String(password);
                    // Get the salt 
                    byte[] salt = new byte[16];
                    Array.Copy(hashBytes, 0, salt, 0, 16);
                    // Compute the hash on the password the user entered
                    var pbkdf2 = new Rfc2898DeriveBytes(loginPassword, salt, 100000);
                    byte[] hash = pbkdf2.GetBytes(20);
                    
                    // Compare the results
                    for (int i=0; i < 20; i++)
                        if (hashBytes[i+16] != hash[i])
                            throw new UnauthorizedAccessException();
                    
                    if (login == loginLogin )
                    {
                        Console.WriteLine("Login and Password are correct!!!!");
                        Console.WriteLine();
                    }
                    else
                    {
                        Console.WriteLine("Login or Password are incorrect");
                        Console.WriteLine();
                        goto case 1;
                    }

                    masterLogin = login;
                    break;
                //Register case
                case 2: 
                    Console.WriteLine("Enter login");
                    String registerLogin = Console.ReadLine();
                    Console.WriteLine("Enter password");
                    String registerPass = Console.ReadLine();

                    if (String.IsNullOrEmpty(registerPass) || String.IsNullOrEmpty(registerLogin))
                    {
                        Console.WriteLine("login or password was not entered");
                        goto case 2;
                    }

                    String pass = CreateHash(registerPass);
                    
                    // //Test outputs
                    //  Console.WriteLine();
                    //  Console.WriteLine(registerLogin);
                    //  Console.WriteLine(registerPass);
                    //  Console.WriteLine(pass);
                    
                    //writes password and login to user file with a hashed password
                    using (StreamWriter writeText = new StreamWriter($"{registerLogin}.txt"))
                    {
                        writeText.WriteLine(registerLogin);
                        writeText.WriteLine(pass);
                        //writeText.Close();
                    }

                    masterLogin = registerLogin;
                    break;
                case 3:
                    return;
                default:
                    Console.WriteLine("Wrong input");
                    return;
            }
            
            //Pick option to search for existing  password or add a new one 
            Start_title:
            Console.WriteLine("1.Search by Title");
            Console.WriteLine("2.Add new password");
            Console.WriteLine("3.Exit");
            x = Convert.ToInt32(Console.ReadLine());

            switch (x)
            {
                //Search by title case
                case 1:
                    Console.WriteLine("Enter Title");
                    String title = Console.ReadLine();

                    String password;
                    
                    try
                    {
                        using (StreamReader readText = new StreamReader($"{masterLogin}_{title}.txt"))
                        {
                            title = readText.ReadLine();
                            password = Decrypt(readText.ReadLine());
                            //writeText.Close();
                        }
                    }
                    catch (FileNotFoundException e)
                    {
                        Console.WriteLine(e);
                        Console.WriteLine();
                        Console.WriteLine("There is no such title");
                        throw;
                    }
                    
                    Start_options:
                    Console.WriteLine("Found password");
                    Console.WriteLine();
                    Console.WriteLine("1.Update password");
                    Console.WriteLine("2.Delete password");
                    Console.WriteLine("3.Copy to clipboard");
                    Console.WriteLine("4.Show");
                    Console.WriteLine("5.Exit");
                    
                    int option = Convert.ToInt32(Console.ReadLine());

                    switch (option)
                    {
                        //update password
                        case 1:
                            Console.WriteLine("enter new passsword");
                            String newPass = Console.ReadLine();
                            using (StreamWriter writeText = new StreamWriter($"{masterLogin}_{title}.txt"))
                            {
                                writeText.WriteLine(title);
                                writeText.WriteLine(Encrypt(newPass));
                                //writeText.Close();
                            }

                            password = newPass;
                            goto Start_options;
                        //Delete password
                        case 2:
                            File.Delete($"{masterLogin}_{title}.txt");
                            Console.WriteLine("Password was deleted");
                            Console.WriteLine();
                            goto Start_title;
                        //Copy to Clipboard password
                        case 3:
                            Clipboard.SetText(password);
                            goto Start_options;
                        //Show case
                        case 4:
                            Console.WriteLine($"Title: {title}");
                            Console.WriteLine($"Password: {password}");
                            goto Start_options;
                        case 5:
                            return;
                        default:
                            Console.WriteLine("Wrong input");
                            return;
                    }
                    
                    break;
                //Add new password case
                case 2:
                    Console.WriteLine("1.Randomly generate password");
                    Console.WriteLine("2.Manually enter password");
                    Console.WriteLine("3.Exit");
                    int n = Convert.ToInt32(Console.ReadLine());

                    switch (n)
                    {
                        //generated password case
                        case 1:
                            Console.WriteLine("What length should the password be?");
                            int length = Convert.ToInt32(Console.ReadLine());

                            String genPassword = RandomString(length);
                            
                            Console.WriteLine("Enter Title");
                            String newTitle = Console.ReadLine();
                            
                            using (StreamWriter writeText = new StreamWriter($"{masterLogin}_{newTitle}.txt"))
                            {
                                writeText.WriteLine(newTitle);
                                writeText.WriteLine(Encrypt(genPassword));
                                //writeText.Close();
                            }
                            break;
                        //manually entered password case
                        case 2:
                            Console.WriteLine("Enter Title");
                            String titleTitle = Console.ReadLine();
                            Console.WriteLine("Enter Password");
                            String titlePassword = Console.ReadLine();
                    
                            using (StreamWriter writeText = new StreamWriter($"{masterLogin}_{titleTitle}.txt"))
                            {
                                writeText.WriteLine(titleTitle);
                                writeText.WriteLine(Encrypt(titlePassword));
                                //writeText.Close();
                            }
                            break;
                        case 3:
                            return;
                        default:
                            Console.WriteLine("Wrong input");
                            break;
                    }
                    break;
                case 3:
                    return;
                default:
                    Console.WriteLine("Wrong Input");
                    return;
            }
        }
    }
}