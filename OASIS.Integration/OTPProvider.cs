/*
    Integration component for the OASIS platform.

    Copyright(c) 2017 Olive Innovations Ltd

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/


using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Net.Http;
using OASIS.Integration.Models;
using System.IO;
using System.Runtime.Serialization.Json;

namespace OASIS.Integration
{
    public class OTPProvider
    {
        private const string OASISServiceURL = "HTTPs://oasis.oliveinnovations.com";
        private long ApplicationID { get; set; }
        private string ApplicationKey { get; set; }
        private string APIKey { get; set; }
        public string DirectoryName { get; set; }
        public string RemoteIP { get; set; }

        #region constructors
        /// <summary>
        /// Initialise new instance 
        /// </summary>
        public OTPProvider()
        {
            this.DirectoryName = ConfigurationManager.AppSettings["OASISDirectoryName"];
            this.APIKey = ConfigurationManager.AppSettings["OASISApiKey"];
            this.ApplicationKey = ConfigurationManager.AppSettings["OASISAppKey"];

            var tempAppID = ConfigurationManager.AppSettings["OASISAppID"];
            long appID = 0;
            if(!long.TryParse(tempAppID,out appID))
            {
                throw new ArithmeticException("OASIS App ID was not found in configration or was not a valid number");
            }

            this.ApplicationID = appID;
        }

        /// <summary>
        /// Initialise new instance of the OASIS OTP Provider
        /// </summary>
        /// <param name="ApplicationID">Application ID from OASIS admin consonsole for the application</param>
        /// <param name="ApplicationKey">Application KEY from OASIS admin consonsole for the application</param>
        /// <param name="APIKey">API KEY from OASIS admin consonsole for the application</param>
        /// <param name="DirectoryName">(Optional) Overwrite issuer name and allow same username over different applications</param>
        /// <param name="remoteIP">(Optional) Remote IP address of request, allows restriction of access based on Geo IP data</param>
        public OTPProvider(long ApplicationID, string ApplicationKey, string APIKey, string DirectoryName = null, string RemoteIP = null)
        {
            this.ApplicationID = ApplicationID;
            this.ApplicationKey = ApplicationKey;
            this.APIKey = APIKey;
            this.DirectoryName = DirectoryName;
            this.RemoteIP = RemoteIP;
        }
        #endregion

        #region RequestAutoisationState
        /// <summary>
        /// Request authorisation state of the user
        /// </summary>
        /// <param name="requestState"></param>
        /// <returns></returns>
        public RequestAuthorisationStateResponse RequestAuthorisationState(RequestAuthorisationState requestState)
        {
            using (Task<RequestAuthorisationStateResponse> runner = RequestAuthorisationStateAsync(requestState))
            {
                return runner.Result;
            }
        }

        /// <summary>
        /// Request authorisation state of the user
        /// </summary>
        /// <param name="requestState"></param>
        /// <returns></returns>
        public async Task<RequestAuthorisationStateResponse> RequestAuthorisationStateAsync(RequestAuthorisationState requestState)
        {
            if (!string.IsNullOrEmpty(DirectoryName) && string.IsNullOrEmpty(requestState.DirectoryName))
                requestState.DirectoryName = DirectoryName;

            var jsonString = JsonSerializer(requestState);
            using (var client = CreateClient(jsonString))
            {
                
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                var result = await client.PostAsync("api/ApplicationAPI/RequestAuthenticationState",content);
                if (result.StatusCode != System.Net.HttpStatusCode.OK) return new RequestAuthorisationStateResponse { State = UserAuthenticatorStateEnum.INVALID };
                var stringResponse = await result.Content.ReadAsStringAsync();
                try
                {
                    var response = JsonDeserialize<RequestAuthorisationStateResponse>(stringResponse);
                    if (VerifySignature(response.SignedResponse, response.RandomToken, requestState.Username, response.State.ToString(), response.SignedTime))
                    {
                        return response;
                    }
                    else
                    {
                        return new RequestAuthorisationStateResponse {
                            State = UserAuthenticatorStateEnum.INVALID
                        };

                    }
                }
                catch
                {
                    return new RequestAuthorisationStateResponse
                    {
                        State = UserAuthenticatorStateEnum.INVALID
                    };
                }
            }
        }
        #endregion

        #region RegisterUser
        public RegisterUserResponse RegisterUser(RegisterUser user)
        {
            using (Task<RegisterUserResponse> runner = RegisterUserAsync(user))
            {
                return runner.Result;
            }
        }

        /// <summary>
        /// Registers a user for application OTP authentication
        /// </summary>
        /// <param name="user">Details of user to register</param>
        /// <returns>RegisterUserResponse</returns>
        public async Task<RegisterUserResponse> RegisterUserAsync(RegisterUser user)
        {
            if (!string.IsNullOrEmpty(DirectoryName) && string.IsNullOrEmpty(user.DirectoryName))
                user.DirectoryName = DirectoryName;

            var jsonString = JsonSerializer(user);

            using (var client = CreateClient(jsonString))
            {
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                var result = await client.PostAsync("api/ApplicationAPI/RegisterUser", content);
                var stringResponse = await result.Content.ReadAsStringAsync();
                return JsonDeserialize<RegisterUserResponse>(stringResponse);
            }
        }
        #endregion

        #region VerifyUserOTP
        public VerifyUserOTPResponse VerifyUserOTP(VerifyUserOTP userOTP)
        {
            using (Task<VerifyUserOTPResponse> runner = VerifyUserOTPAsync(userOTP))
            {
                return runner.Result;
            }
        }

        /// <summary>
        /// Verifies a registered users OTP code
        /// </summary>
        /// <param name="userOTP">User details including OTP</param>
        /// <returns>VerifyUserOTPResponse</returns>
        public async Task<VerifyUserOTPResponse> VerifyUserOTPAsync(VerifyUserOTP userOTP)
        {
            if (!string.IsNullOrEmpty(DirectoryName) && string.IsNullOrEmpty(userOTP.DirectoryName))
                userOTP.DirectoryName = DirectoryName;

            var jsonString = JsonSerializer(userOTP);

            using (var client = CreateClient(jsonString))
            {
                
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                var result = await client.PostAsync("api/ApplicationAPI/VerifyUserOTP", content);
                var stringResponse = await result.Content.ReadAsStringAsync();
                try
                {
                    var response = JsonDeserialize<VerifyUserOTPResponse>(stringResponse);
                    string userID = userOTP.Username;
                    if (VerifySignature(response.SignedResponse,response.RandomToken, userID, response.State.ToString(),response.SignedTime))
                    {
                        return response;
                    }
                    else
                    {
                        return new Models.VerifyUserOTPResponse
                    {
                        State = UserAuthenticatorStateEnum.INVALID
                    };
                    }

                }catch(Exception e)
                {
                    return new Models.VerifyUserOTPResponse
                    {
                        State = UserAuthenticatorStateEnum.INVALID
                    };
                }
            }
        }
        #endregion

        #region DeleteUser
        public bool DeleteUser(string userName, string directoryName = null)
        {
            using (Task<bool> runner = DeleteUserAsync(userName,directoryName))
            {
                return runner.Result;
            }
        }

        /// <summary>
        /// Delete user
        /// </summary>
        /// <param name="userName">Username to delete</param>
        /// <returns>true if successful or false</returns>
        public async Task<bool> DeleteUserAsync(string userName, string directoryName = null)
        {
            if (!string.IsNullOrEmpty(DirectoryName) && string.IsNullOrEmpty(directoryName))
                directoryName = DirectoryName;

            using (var client = CreateClient(""))
            {
                var result = await client.DeleteAsync("api/ApplicationAPI/DeleteUser?userName=" + (!string.IsNullOrEmpty(directoryName) ? directoryName + "\\" : "") + userName);
                return (result.StatusCode == System.Net.HttpStatusCode.OK);
            }
        }
        #endregion

        #region HelloWorld used to test API Key, App Key and AppID are valid
        public bool HelloWorld()
        {
            using (Task<bool> runner = HelloWorldAsync())
            {
                return runner.Result;
            }
        }

        public async Task<bool> HelloWorldAsync()
        {
            using (var client = CreateClient(""))
            {
                var result = await client.GetAsync("api/ApplicationAPI/HelloWorld");
                return (result.StatusCode == System.Net.HttpStatusCode.OK);
            }
        }
        #endregion

        #region Helper Methods
        private HttpClient CreateClient(string content)
        {
            var client = new HttpClient()
            {
                BaseAddress = new Uri(OASISServiceURL)
            };
            var thisepoch = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;
            var reqsecret = "";
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(APIKey)))
            {
                var hashData = Encoding.UTF8.GetBytes(string.Format("{0}:{1}:{2}:{3}{4}"
                                , ApplicationID
                                , thisepoch
                                , ApplicationKey
                                , content
                                , (!string.IsNullOrEmpty(RemoteIP) ? ":" + RemoteIP : "")));
                var hmacHash = hmac.ComputeHash(hashData);
                reqsecret = Convert.ToBase64String(hmacHash);
            }

            client.DefaultRequestHeaders.Add("X-OASIS-EPOCH", thisepoch.ToString());
            client.DefaultRequestHeaders.Add("X-OASIS-APPID", ApplicationID.ToString());
            client.DefaultRequestHeaders.Add("X-OASIS-REQSECRET", reqsecret);
            if (!string.IsNullOrEmpty(RemoteIP))
                client.DefaultRequestHeaders.Add("X-OASIS-IP", RemoteIP);

            return client;
        }

        public static T JsonDeserialize<T>(string jsonString)
        {
            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(T));
            using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(jsonString)))
            {
                T obj = (T)ser.ReadObject(ms);
                return obj;
            }
        }

        public static string JsonSerializer<T>(T t)
        {
            DataContractJsonSerializer ser = new DataContractJsonSerializer(typeof(T));
            using (MemoryStream ms = new MemoryStream())
            {
                ser.WriteObject(ms, t);
                string jsonString = Encoding.UTF8.GetString(ms.ToArray());
                ms.Close();
                return jsonString;
            }
        }

        private bool VerifySignature(string signedResponse,string randomData, string data1, string data2, long signedTime)
        {
            using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(ApplicationKey)))
            {
                var thisepoch = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds;

                if (signedTime < (thisepoch - (5 * 60))) return false;

                var hashData = Encoding.UTF8.GetBytes(string.Format("{0}:{1}:{2}:{3}", data1, data2,randomData,signedTime));
                var hmacHash = hmac.ComputeHash(hashData);
                var base64Hash = Convert.ToBase64String(hmacHash);

                return base64Hash.Equals(signedResponse, StringComparison.InvariantCulture);
            }
        }
        #endregion
    }
}
