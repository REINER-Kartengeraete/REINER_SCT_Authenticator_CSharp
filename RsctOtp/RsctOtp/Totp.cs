// MIT LICENSE
//
// $Date: Wed Jul 22 11:43:18 2020 +0200$
// $Rev: v1.0.0-18-ge8d4816$

using System;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;

namespace RsctOtp
{
    public class Totp : Otp
    {
        /// <summary>
        /// The number of ticks as Measured at Midnight Jan 1st 1970;
        /// </summary>
        public const long unixEpochTicks = 621355968000000000L;
        /// <summary>
        /// A divisor for converting ticks to seconds
        /// </summary>
        public const long ticksToSeconds = 10000000L;

        protected const int DEFAULT_INTERVAL = 30;

        private readonly int interval;
        private readonly string issuer;

        public Totp(string secret, string issuer = null, int interval = DEFAULT_INTERVAL, Digest digest = DEFAULT_DIGEST, int digits = DEFAULT_DIGITS) : base(secret, digest, digits)
        {
            this.interval = interval;
            this.issuer = issuer;
        }

        public string At(DateTime time)
        {
            return GenerateOtp(CalculateTimeStepFromTimestamp(time));
        }

        public string At(int timestep)
        {
            return GenerateOtp(timestep / this.interval);
        }

        public string Now()
        {
            return At(DateTime.Now);
        }

        public int? Verify(string otp, int driftAhead = 0, int driftBehind = 0, DateTime? at = null, DateTime? after = null)
        {
            int[] timesteps = CalculateTimeSteps((at ?? DateTime.UtcNow), driftAhead, driftBehind, after);
            int? result = null;
            foreach (int step in timesteps)
            {
                if (otp == GenerateOtp(step))
                {
                    result = step * this.interval;
                }
            }
            return result;
        }

        public string ProvisioningUri(string name)
        {
            NameValueCollection uriParams = new NameValueCollection()
            {
                { "secret", this.secret },
                { "period", this.interval == DEFAULT_INTERVAL ? null : this.interval.ToString() },
                { "issuer", this.issuer },
                { "digits", this.digits == DEFAULT_DIGITS ? null : this.digits.ToString() },
                { "algorithm", this.digest == DEFAULT_DIGEST ? null : this.digest.ToString().ToUpper() }
            };
            string issuer_string = this.issuer == null ? "" : System.Web.HttpUtility.UrlPathEncode(this.issuer) + ":";
            string path = "otpauth://totp/" + issuer_string + System.Web.HttpUtility.UrlPathEncode(name);
            return EncodeParams(path, uriParams);
        }

        private string EncodeParams(string path, NameValueCollection uriParams)
        {
            string paramsString = "?";

            foreach (string key in uriParams)
            {
                string value = uriParams[key];
                if (value != null)
                {
                    // WARNING: Should be UrlEncode instead UrlPathEncode,
                    //          but Google Authenticator Example want's '%20' instead '+'
                    paramsString += key + "=" + System.Web.HttpUtility.UrlPathEncode(value) + "&";
                }
            }
            paramsString = paramsString.Remove(paramsString.Length - 1);
            return path + paramsString;
        }

        private int[] CalculateTimeSteps(DateTime at, int driftAhead, int driftBehind, DateTime? after = null)
        {
            int unixTimestamp = (int)((at.Ticks - unixEpochTicks) / ticksToSeconds);
            int first = (unixTimestamp - driftBehind) / this.interval;
            int last = (unixTimestamp + driftAhead) / this.interval;
            var range = Enumerable.Range((int)first, ((int)(last - first + 1)));
            if (after.HasValue)
            {
                int afterStep = CalculateTimeStepFromTimestamp(after.GetValueOrDefault(DateTime.Now));
                range = range.Where(i => i > afterStep);
            }
            return range.ToArray();
        }

        /// <summary>
        /// Takes a timestamp and calculates a time step
        /// </summary>
        private int CalculateTimeStepFromTimestamp(DateTime timestamp)
        {
            var unixTimestamp = (int)((timestamp.Ticks - unixEpochTicks) / ticksToSeconds);
            var window = unixTimestamp / (int)this.interval;
            return window;
        }


    }
}
