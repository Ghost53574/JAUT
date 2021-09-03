using System;
using System.IO.Compression;

namespace Packer {
    class Program {
        static byte[] RC4(byte[] input, byte[] key) {
            byte[] result = new byte[input.Length];
            int x, y, j = 0;
            int[] box = new int[256];
            for (int i = 0; i < 256; i++)
                box[i] = i;
            for (int i = 0; i < 256; i++) {
                j = (key[i % key.Length] + box[i] + j) % 256;
                x = box[i];
                box[i] = box[j];
                box[j] = x;
            }
            for (int i = 0; i < input.Length; i++) {
                y = i % 256;
                j = (box[y] + j) % 256;
                x = box[y];
                box[y] = box[j];
                box[j] = x;
                result[i] = (byte)(input[i] ^ box[(box[y] + box[j]) % 256]);
            }
            return result;
        }

        static readonly string banner = "* * * * * * * * * * * * * * * *\n* ./encrypt <key> <img> <exe> <out> *\n* * * * * * * * * * * * * * * *\n*note: full paths please";

        static void Main(string[] args) {
            uint file_size_bytes = 0;
            uint image_size_bytes = 0;

            if (args.Length != 4) {
                Console.WriteLine(Program.banner);
                return;
            }

            string password = args[0];
            string image_path = args[1]; // Could be anything that supports writing paste the EOF, I just am using images
            string file_path = args[2];
            string payload_path = args[3];

            if (!System.IO.File.Exists(file_path)) {
                Console.WriteLine("{0} does not exist!", file_path);
                return;
            }
            if (!System.IO.File.Exists(image_path)) {
                Console.WriteLine("{0} does not exist!", image_path);
                return;
            }
            if (System.IO.File.Exists(payload_path)) {
                Console.WriteLine("Overwriting {0}...", payload_path);
                System.IO.File.Delete(payload_path);
            }

            image_size_bytes = (uint)new System.IO.FileInfo(image_path).Length;
            file_size_bytes = (uint)new System.IO.FileInfo(file_path).Length;

            Console.WriteLine("Input file total size:\t{0}", file_size_bytes);

            // Some DEADBEEF action here               v
            byte[] image = new byte[image_size_bytes + 4 + file_size_bytes];

            using (System.IO.Stream i = System.IO.File.Open(image_path, System.IO.FileMode.Open)) {
                i.Seek(0, System.IO.SeekOrigin.Begin);
                i.Read(image);
                i.Dispose();
                i.Close();
            }
            byte[] mimi = new byte[file_size_bytes];
            using (System.IO.Stream m = System.IO.File.Open(file_path, System.IO.FileMode.Open)) {
                m.Seek(0, System.IO.SeekOrigin.Begin);
                m.Read(mimi);
                m.Dispose();
                m.Close();
            }
            Console.WriteLine("Image total size:\t{0}", image.Length);
            // Magic
            image[image_size_bytes + 1] = 0xDE;
            image[image_size_bytes + 2] = 0xAD;
            image[image_size_bytes + 3] = 0xBE;
            image[image_size_bytes + 4] = 0xEF;
            image_size_bytes += 4;

            mimi = Program.RC4(mimi, System.Text.Encoding.ASCII.GetBytes(password));

            using (System.IO.MemoryStream ms = new System.IO.MemoryStream()) {
                using (GZipStream gz = new GZipStream(ms, CompressionLevel.Optimal)) {
                    gz.Write(mimi, 0, (int)file_size_bytes);
                    ms.Seek(0, System.IO.SeekOrigin.Begin);
                }

                byte[] gz_bytes = ms.ToArray();

                Console.WriteLine("GZ bytes:\t{0}", gz_bytes.Length);

                for (int i = 0; i < gz_bytes.Length; i++) {
                    image[image_size_bytes + i] = gz_bytes[i];
                }

                image_size_bytes += (uint)gz_bytes.Length;

                Console.WriteLine("Free bytes:\t{0}", ((int)file_size_bytes - (int)image_size_bytes));

                using (System.IO.FileStream fs = new System.IO.FileStream(payload_path, System.IO.FileMode.CreateNew)) {
                    fs.Write(image, 0, (int)image_size_bytes);
                    fs.Dispose();
                    fs.Close();
                }
                ms.Dispose();
                ms.Close();
            }
        }
    }
}
