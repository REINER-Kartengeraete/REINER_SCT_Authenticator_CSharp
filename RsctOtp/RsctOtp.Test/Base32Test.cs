// MIT LICENSE
//
// $Date: Wed Jul 22 11:43:18 2020 +0200$
// $Rev: v1.0.0-18-ge8d4816$

using System;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace RsctOtp.Test
{
    [TestClass]
    public class Base32Test
    {
        [TestMethod]
        public void TestRandomWithoutArguments()
        {
            string testSecret = Base32.Random();

            Assert.AreEqual(20, Base32.Decode(testSecret).Length);
            Assert.AreEqual(32, testSecret.Length);

            StringAssert.Matches(testSecret, new Regex("^[A-Z2-7]+$"));
        }

        [TestMethod]
        public void TestRandomWithArguments()
        {
            string testSecret = Base32.Random(48);

            Assert.AreEqual(48, Base32.Decode(testSecret).Length);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentException),
            "Character is not a Base32 character.")]
        public void TestDecodeArgumentException()
        {
            Base32.Decode("4BCDEFG234BCDEF1");
        }

        [TestMethod]
        public void TestDecodeNormalInput()
        {
            Base32.Decode("HQQE3KKCST7YEEB64NHJN52LJA");
            Assert.AreEqual("d103f17bd6176727", UnpackHex(Base32.Decode("2EB7C66WC5TSO")));
            Assert.AreEqual("c7b1dc8802fb40111e49", UnpackHex(Base32.Decode("Y6Y5ZCAC7NABCHSJ")));
        }

        [TestMethod]
        public void TestDecodeInputWithTrailingBits()
        {
            Assert.AreEqual("c567eceae5e0609685931fd9e8060223", UnpackHex(Base32.Decode("YVT6Z2XF4BQJNBMTD7M6QBQCEM")));
            Assert.AreEqual("e98d9807766f963fd76be9de3c4e140349", UnpackHex(Base32.Decode("5GGZQB3WN6LD7V3L5HPDYTQUANEQ")));
        }

        [TestMethod]
        public void TestDecodeInputWithPadding()
        {
            Assert.AreEqual("d6f8", UnpackHex(Base32.Decode("234A===")));
        }

        [TestMethod]
        public void TestEncode()
        {
            Assert.AreEqual("HQQE3KKCST7YEEB64NHJN52LJA", Base32.Encode(PackHex("3c204da94294ff82103ee34e96f74b48")));
        }


        private string UnpackHex(byte[] bytes)
        {
            string outputString = "";
            outputString = BitConverter.ToString(bytes).Replace("-", "").ToLower();
            //for (int byteArrayPosition = 0; byteArrayPosition < bytes.Length; byteArrayPosition++)
            //{
            //    outputString += BitConverter.ToUInt16(bytes, byteArrayPosition).ToString("x2");
            //}
            return outputString;
        }

        private byte[] PackHex(string str)
        {
            return Enumerable.Range(0, str.Length / 2)
                .Select(i => Convert.ToByte(str.Substring(i * 2, 2), 16))
                .ToArray();
        }
    }
}
