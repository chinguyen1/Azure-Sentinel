using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace nsgFunc
{
	public partial class Util
	{
		public static async Task<int> obLogAnalytics(string newClientContent, ILogger log)
		{
			// Update customerId to your Log Analytics workspace ID
			string customerId = Util.GetEnvironmentVariable("customerId");

			// For sharedKey, use either the primary or the secondary Connected Sources client authentication key   
			string sharedKey = Util.GetEnvironmentVariable("sharedKey");

			// LogName is name of the event type that is being submitted to Azure Monitor
			string LogName = "NSGFlowLogs";

			// You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
			string TimeStampField = "";

			var records = denormalizedRecords(newClientContent, null, log);

			string serialized = JsonConvert.SerializeObject(records, new JsonSerializerSettings
			{
				ContractResolver = new DefaultContractResolver
				{
					NamingStrategy = new CamelCaseNamingStrategy()
				}
			});
			serialized = serialized.Replace("[[", "[").Replace("]]", "]");

			//string serialized = @"[{""DemoField1"":""DemoValue1"",""DemoField2"":""DemoValue2""},{""DemoField3"":""DemoValue3"",""DemoField4"":""DemoValue4""}]";

			// Create a hash for the API signature
			var datestring = DateTime.UtcNow.ToString("r");
			var jsonBytes = Encoding.UTF8.GetBytes(serialized);
			string stringToHash = "POST\n" + jsonBytes.Length + "\napplication/json\n" + "x-ms-date:" + datestring + "\n/api/logs";
			string hashedString = BuildSignature(stringToHash, sharedKey);
			string signature = "SharedKey " + customerId + ":" + hashedString;

			try
			{
				string url = "https://" + customerId + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01";

				HttpClient client = new HttpClient();
				client.DefaultRequestHeaders.Add("Accept", "application/json");
				client.DefaultRequestHeaders.Add("Log-Type", LogName);
				client.DefaultRequestHeaders.Add("Authorization", signature);
				client.DefaultRequestHeaders.Add("x-ms-date", datestring);
				client.DefaultRequestHeaders.Add("time-generated-field", TimeStampField);

				System.Net.Http.HttpContent httpContent = new StringContent(serialized, Encoding.UTF8);
				httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
				HttpResponseMessage response = await client.PostAsync(new Uri(url), httpContent);

				if (response.StatusCode != HttpStatusCode.OK)
				{
					log.LogError($"StatusCode from Loganalytics: {response.StatusCode}, and reason: {response.ReasonPhrase}");
				}
				System.Net.Http.HttpContent responseContent = response.Content;
				string result = responseContent.ReadAsStringAsync().Result;

				log.LogInformation("Return Result: " + result);

				return jsonBytes.Length;
			}
			catch (Exception ex)
			{
				log.LogError($"Unknown error caught while sending to Loganalytics: \"{ex.Message}\"");
				throw ex;
			}
		}

		// Build the API signature
		public static string BuildSignature(string message, string secret)
		{
			var encoding = new System.Text.ASCIIEncoding();
			byte[] keyByte = Convert.FromBase64String(secret);
			byte[] messageBytes = encoding.GetBytes(message);
			using (var hmacsha256 = new HMACSHA256(keyByte))
			{
				byte[] hash = hmacsha256.ComputeHash(messageBytes);
				return Convert.ToBase64String(hash);
			}
		}
	}
}
