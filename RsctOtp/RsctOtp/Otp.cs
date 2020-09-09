// MIT LICENSE
//
// $Date: Wed Jul 22 11:43:18 2020 +0200$
// $Rev: v1.0.0-18-ge8d4816$

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace RsctOtp
{

    public class Otp
    {
        protected readonly string secret;
        protected readonly Digest digest;
        protected readonly int digits;

        protected const int DEFAULT_DIGITS = 6;
        protected const Digest DEFAULT_DIGEST = Digest.Sha1;

        public Otp(string secret, Digest digest = DEFAULT_DIGEST, int digits = DEFAULT_DIGITS)
        {
            this.secret = secret;
            this.digest = digest;
            this.digits = digits;
        }

        public string GenerateOtp(int input)
        {
            // Since .net uses little endian numbers, we need to reverse the byte order to get big endian.
            var data = BitConverter.GetBytes((long)input);
            Array.Reverse(data);

            HMAC hmac = null;
            switch (this.digest)
            {
                case Digest.Sha256:
                    hmac = new HMACSHA256();
                    break;
                case Digest.Sha512:
                    hmac = new HMACSHA512();
                    break;
                default: //case Digest.Sha1:
                    hmac = new HMACSHA1();
                    break;
            }
            hmac.Key = Base32.Decode(this.secret);
            byte[] hashedValue = hmac.ComputeHash(data);

            int offset = hashedValue[hashedValue.Length - 1] & 0x0F;
            long result = (hashedValue[offset] & 0x7f) << 24
                            | (hashedValue[offset + 1] & 0xff) << 16
                            | (hashedValue[offset + 2] & 0xff) << 8
                            | (hashedValue[offset + 3] & 0xff) % 1000000;

            var truncatedValue = ((int)result % (int)Math.Pow(10, this.digits));
            return truncatedValue.ToString().PadLeft(this.digits, '0');
        }
    }
}
