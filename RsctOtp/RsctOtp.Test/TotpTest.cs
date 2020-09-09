// MIT LICENSE
//
// $Date: Wed Jul 22 11:43:18 2020 +0200$
// $Rev: v1.0.0-18-ge8d4816$

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace RsctOtp.Test
{
    [TestClass]
    public class TotpTest
    {
        DateTime TEST_TIME = new DateTime(2016, 9, 23, 9, 0, 0, DateTimeKind.Utc);
        const string TEST_TOKEN = "082630";
        const string TEST_SECRET = "JBSWY3DPEHPK3PXP";

        private Totp createTotp(string secret = TEST_SECRET)
        {
            return new Totp(secret);
        }

        [TestMethod]
        public void AtSimple()
        {
            Assert.AreEqual(TEST_TOKEN, createTotp().At(TEST_TIME));
        }

        [TestMethod]
        public void AtRfcExamples()
        {
            Totp totp = createTotp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

            Assert.AreEqual("050471", totp.At(1111111111));
            Assert.AreEqual("005924", totp.At(1234567890));
            Assert.AreEqual("279037", totp.At(2000000000));
        }

        [TestMethod]
        public void VerifyFailUnpadded()
        {
            Assert.IsNull(createTotp().Verify("82630", at: TEST_TIME));
        }

        [TestMethod]
        public void VerifyCorrectly()
        {
            Assert.IsNotNull(createTotp().Verify(TEST_TOKEN, at: TEST_TIME));
        }

        [TestMethod]
        public void VerifyRfcExamples()
        {
            Totp totp = createTotp("wrn3pqx5uqxqvnqr");

            DateTime time = DateTimeOffset.FromUnixTimeSeconds(1297553958).DateTime;
            Assert.IsNotNull(totp.Verify("102705", at: time));

            Assert.IsNull(createTotp().Verify("102705"));
        }

        [TestMethod]
        public void VerifyFailsWithReusedToken()
        {
            int? afterTimestamp = createTotp().Verify(TEST_TOKEN, at: TEST_TIME);
            Assert.IsTrue(afterTimestamp.HasValue);

            //FIXME: Convenience method for converting timestamp into DateTime object???
            var testTimeTimestamp = (int)((TEST_TIME.Ticks - Totp.unixEpochTicks) / Totp.ticksToSeconds);

            Assert.IsTrue(afterTimestamp > testTimeTimestamp - 30 && afterTimestamp < testTimeTimestamp + 30);

            DateTime after = DateTimeOffset.FromUnixTimeSeconds(afterTimestamp ?? 0).DateTime;

            Assert.IsNull(createTotp().Verify(TEST_TOKEN, at: TEST_TIME, after: after));
        }

        [TestMethod]
        public void CalculateTimeStepsBehind()
        {
            CollectionAssert.AreEqual(new int[] { 49_154_040 }, InvokeCalculateTimeSteps(TEST_TIME.AddSeconds(15), 15, 0));
            CollectionAssert.AreEqual(new int[] { 49_154_039, 49_154_040 }, InvokeCalculateTimeSteps(TEST_TIME, 15, 0));
            CollectionAssert.AreEqual(new int[] { 49_154_038, 49_154_039, 49_154_040 }, InvokeCalculateTimeSteps(TEST_TIME, 40, 0));
            CollectionAssert.AreEqual(new int[] { 49_154_037, 49_154_038, 49_154_039, 49_154_040 }, InvokeCalculateTimeSteps(TEST_TIME, 90, 0));
        }

        [TestMethod]
        public void CalculateTimeStepsAhead()
        {
            CollectionAssert.AreEqual(new int[] { 49_154_040 }, InvokeCalculateTimeSteps(TEST_TIME, 0, 15));
            CollectionAssert.AreEqual(new int[] { 49_154_040, 49_154_041 }, InvokeCalculateTimeSteps(TEST_TIME.AddSeconds(15), 0, 15));
            CollectionAssert.AreEqual(new int[] { 49_154_040, 49_154_041 }, InvokeCalculateTimeSteps(TEST_TIME, 0, 30));
            CollectionAssert.AreEqual(new int[] { 49_154_040, 49_154_041, 49_154_042 }, InvokeCalculateTimeSteps(TEST_TIME, 0, 70));
            CollectionAssert.AreEqual(new int[] { 49_154_040, 49_154_041, 49_154_042, 49_154_043 }, InvokeCalculateTimeSteps(TEST_TIME, 0, 90));
        }

        [TestMethod]
        public void CalculateTimeStepsBehindAndAhead()
        {
            CollectionAssert.AreEqual(new int[] { 49_154_039, 49_154_040, 49_154_041 }, InvokeCalculateTimeSteps(TEST_TIME, 30, 30));
            CollectionAssert.AreEqual(new int[] { 49_154_038, 49_154_039, 49_154_040, 49_154_041, 49_154_042 }, InvokeCalculateTimeSteps(TEST_TIME, 60, 60));
        }

        private int[] InvokeCalculateTimeSteps(DateTime at, int driftBehind, int driftAhead)
        {
            Type type = typeof(Totp);
            var totp = Activator.CreateInstance(type, new object[] { TEST_SECRET, null, 30, Digest.Sha1, 6 });
            MethodInfo method = type.GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)
                .Where(x => x.Name == "CalculateTimeSteps" && x.IsPrivate)
                .First();

            // WARNING: Different order of driftAhead and driftBehind!!!
            return (int[])method.Invoke(totp, new object[] { at, driftAhead, driftBehind, null });
        }

        [TestMethod]
        public void VerifyWithDriftAndOldOtp()
        {
            Totp totp = createTotp();
            string oldToken = totp.At(TEST_TIME.AddSeconds(-30));
            Assert.IsNotNull(totp.Verify(oldToken, 0, 15, TEST_TIME));
            Assert.IsNull(totp.Verify(oldToken, 0, 15, TEST_TIME.AddSeconds(20)));
        }

        [TestMethod]
        public void VerifyWithDriftAndFutureOtp()
        {
            Totp totp = createTotp();
            string futureToken = totp.At(TEST_TIME.AddSeconds(30));
            Assert.IsNull(totp.Verify(futureToken, 15, 0, TEST_TIME));
            Assert.IsNotNull(totp.Verify(futureToken, 15, 0, TEST_TIME.AddSeconds(20)));
        }

        [TestMethod]
        public void VerifyWithDriftAndOldOtpPreventTokenReuse()
        {
            Totp totp = createTotp();
            string oldToken = totp.At(TEST_TIME.AddSeconds(-30));
            int expected = (int)((TEST_TIME.AddSeconds(-30).Ticks - Totp.unixEpochTicks) / Totp.ticksToSeconds);
            Assert.AreEqual(expected, totp.Verify(oldToken, 0, 15, TEST_TIME));

            DateTime after = DateTimeOffset.FromUnixTimeSeconds((long)totp.Verify(oldToken, 0, 15, TEST_TIME)).DateTime;
            Assert.IsNull(totp.Verify(oldToken, 0, 15, TEST_TIME, after));
        }

        [TestMethod]
        public void VerifyWithDriftAndFutureOtpPreventTokenReuse()
        {
            Totp totp = createTotp();
            string futureToken = totp.At(TEST_TIME.AddSeconds(30));
            int expected = (int)((TEST_TIME.AddSeconds(30).Ticks - Totp.unixEpochTicks) / Totp.ticksToSeconds);
            Assert.AreEqual(expected, totp.Verify(futureToken, 15, 0, TEST_TIME.AddSeconds(15)));

            DateTime after = DateTimeOffset.FromUnixTimeSeconds((long)totp.Verify(futureToken, 15, 0, TEST_TIME.AddSeconds(15))).DateTime;
            Assert.IsNull(totp.Verify(futureToken, 15, 0, TEST_TIME.AddSeconds(15), after));
        }

        [TestMethod]
        public void ProvisioningUriSpaceInName()
        {
            string uri = createTotp().ProvisioningUri("ben von tuxwerk");

            NameValueCollection uriParams = GetParams(uri);

            Assert.AreEqual("otpauth://totp/ben%20von%20tuxwerk?secret=JBSWY3DPEHPK3PXP", uri);

            Assert.AreEqual(TEST_SECRET, uriParams["secret"]);
        }

        [TestMethod]
        public void ProvisioningUriWithoutIssuer()
        {
            string uri = createTotp().ProvisioningUri("ben@tuxwerk.de");

            NameValueCollection uriParams = GetParams(uri);

            StringAssert.Matches(uri, new System.Text.RegularExpressions.Regex("^otpauth:\\/\\/totp.+"));

            Assert.AreEqual(TEST_SECRET, uriParams["secret"]);
        }

        [TestMethod]
        public void ProvisioningUriWithDefaultDigits()
        {
            string uri = createTotp().ProvisioningUri("ben@tuxwerk.de");

            NameValueCollection uriParams = GetParams(uri);

            Assert.IsNull(uriParams["digits"]);
        }

        [TestMethod]
        public void ProvisioningUriWithNonDefaultDigits()
        {
            Totp totp = new Totp(TEST_SECRET, digits: 8);
            string uri = totp.ProvisioningUri("ben@tuxwerk.de");

            NameValueCollection uriParams = GetParams(uri);

            Assert.AreEqual("8", uriParams["digits"]);
        }

        [TestMethod]
        public void ProvisioningUriWithIssuer()
        {
            Totp totp = new Totp(TEST_SECRET, issuer: "FooCo");
            string uri = totp.ProvisioningUri("ben@tuxwerk.de");

            NameValueCollection uriParams = GetParams(uri);

            StringAssert.Matches(uri, new System.Text.RegularExpressions.Regex("^otpauth:\\/\\/totp/FooCo:.+"));

            Assert.AreEqual(TEST_SECRET, uriParams["secret"]);
            Assert.AreEqual("FooCo", uriParams["issuer"]);
        }

        [TestMethod]
        public void ProvisioningUriWithSpacesInIssuer()
        {
            Totp totp = new Totp(TEST_SECRET, issuer: "Foo Co");
            string uri = totp.ProvisioningUri("ben@tuxwerk.de");

            NameValueCollection uriParams = GetParams(uri);

            Assert.AreEqual("otpauth://totp/Foo%20Co:ben@tuxwerk.de?secret=JBSWY3DPEHPK3PXP&issuer=Foo%20Co", uri);

            Assert.AreEqual(TEST_SECRET, uriParams["secret"]);

            Assert.AreEqual("Foo Co", uriParams["issuer"]);
        }

        [TestMethod]
        public void ProvisioningUriWithCustomInterval()
        {
            Totp totp = new Totp(TEST_SECRET, interval: 60);
            string uri = totp.ProvisioningUri("ben@tuxwerk.de");

            NameValueCollection uriParams = GetParams(uri);

            Assert.AreEqual("60", uriParams["period"]);
        }

        [TestMethod]
        public void ProvisioningUriWithCustomDigest()
        {
            Totp totp = new Totp(TEST_SECRET, digest: Digest.Sha256);
            string uri = totp.ProvisioningUri("ben@tuxwerk.de");

            NameValueCollection uriParams = GetParams(uri);

            Assert.AreEqual("SHA256", uriParams["algorithm"]);
        }

        private NameValueCollection GetParams(string uri)
        {
            string queryString = new System.Uri(uri).Query;
            return System.Web.HttpUtility.ParseQueryString(queryString);
        }

        [TestMethod]
        public void Now()
        {
            //FIXME: C# doesn't support mocking of DateTime, so the only possibility
            //       is to create an interface providing the current date within the
            //       TOTP object and mock that

            // Example for Google Authenticator
            Totp totpGoogle = new Totp("wrn3pqx5uqxqvnqr");
            DateTime nowGoogle = DateTimeOffset.FromUnixTimeSeconds(1_297_553_958).DateTime;
            Assert.AreEqual("102705", totpGoogle.At(nowGoogle));

            // Example for Dropbox 26 char secret output
            Totp totpDropbox = new Totp("tjtpqea6a42l56g5eym73go2oa");
            DateTime nowDropbox = DateTimeOffset.FromUnixTimeSeconds(1_378_762_454).DateTime;
            Assert.AreEqual("747864", totpDropbox.At(nowDropbox));

        }
    }
}
