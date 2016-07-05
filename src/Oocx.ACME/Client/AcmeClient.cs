﻿using System;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Oocx.ACME.Jose;
using Oocx.ACME.Protocol;
using Oocx.ACME.Services;
using Oocx.Asn1PKCS.Asn1BaseTypes;
using static Oocx.ACME.Common.Log;

namespace Oocx.ACME.Client
{
    public class AcmeClient : IAcmeClient
    {        
        private readonly HttpClient client;

        private Directory directory;

        private string nonce;        

        private readonly JWS jws;

        public AcmeClient(HttpClient client, RSA key)
        {
            Info($"using server {client.BaseAddress}");

            this.client = client;
            jws = new JWS(key);            
        }

        public AcmeClient(string baseAddress, string keyName, IKeyStore keyStore): this(new HttpClient() { BaseAddress =  new Uri(baseAddress) }, keyStore.GetOrCreateKey(keyName))
        {         
        }

        public string GetKeyAuthorization(string token)
        {
            return jws.GetKeyAuthorization(token);
        }

        public async Task<Directory> DiscoverAsync()
        {
            Verbose($"Querying directory information from {client.BaseAddress}" );
            return await GetAsync<Directory>(new Uri("directory", UriKind.Relative)).ConfigureAwait(false);            
        }

        private void RememberNonce(HttpResponseMessage response)
        {
            nonce = response.Headers.GetValues("Replay-Nonce").First();
            Verbose($"nonce from server is {nonce}");
        }

        public async Task<RegistrationResponse> RegisterAsync(string termsOfServiceUri, string[] contact)
        {
            await EnsureDirectory().ConfigureAwait(false);            

            Info("trying to create new registration");

            var request = new NewRegistrationRequest()
            {                            
                Contact = contact,
                Agreement = termsOfServiceUri
            };

            try
            {
                var registration = await PostAsync<RegistrationResponse>(directory.NewRegistration, request).ConfigureAwait(false);
                Info($"new registration created: {registration.Location}");
                
                return registration;
            }
            catch (AcmeException ex) when ((int) ex.Response.StatusCode == 409)
            {
                var location = ex.Response.Headers.Location.ToString();
                Info($"using existing registration: {location}");
                var response =  await PostAsync<RegistrationResponse>(new Uri(location), new UpdateRegistrationRequest()).ConfigureAwait(false);
                if (string.IsNullOrEmpty(response.Location))
                {
                    response.Location = location;
                }
                return response;
            }            
        }

        public async Task EnsureDirectory()
        {
            if (directory == null || nonce == null)
            {
                directory = await DiscoverAsync().ConfigureAwait(false);
            }
        }

        public async Task<RegistrationResponse> UpdateRegistrationAsync(string registrationUri, string termsOfServiceUri, string[] contact)
        {
            await EnsureDirectory().ConfigureAwait(false);

            Info("updating registration: accepting terms of service");

            var registration = new UpdateRegistrationRequest()
            {                
                Contact = contact,
                Agreement = termsOfServiceUri
            };

            return await PostAsync<RegistrationResponse>(new Uri(registrationUri), registration).ConfigureAwait(false);
        }

        public async Task<AuthorizationResponse> NewDnsAuthorizationAsync(string dnsName)
        {
            await EnsureDirectory().ConfigureAwait(false);

            Info($"requesting authorization for dns identifier {dnsName}");            

            var authorization = new AuthorizationRequest()
            {
                Resource = "new-authz",
                Identifier = new Identifier() {  Type = "dns", Value = dnsName}
            };

            return await PostAsync<AuthorizationResponse>(directory.NewAuthorization, authorization).ConfigureAwait(false);
        }                    

        public async Task<Challenge> CompleteChallengeAsync(Challenge challenge)
        {           
            var challangeRequest = new KeyAuthorizationRequest()
            {
                KeyAuthorization = jws.GetKeyAuthorization(challenge.Token)
            };

            challenge = await PostAsync<Challenge>(challenge.Uri, challangeRequest).ConfigureAwait(false);

            while ("pending".Equals(challenge?.Status, StringComparison.OrdinalIgnoreCase))
            {
                await Task.Delay(4000).ConfigureAwait(false);
                challenge = await GetAsync<Challenge>(challenge.Uri).ConfigureAwait(false);                                
            }

            Info($"challenge status is {challenge?.Status}");
            if (challenge?.Error?.Type != null)
            {
                Error($"{challenge.Error.Type} : {challenge.Error.Detail}");
            }


            return challenge;
        }

        public async Task<CertificateResponse> NewCertificateRequestAsync(byte[] csr)
        {
            await EnsureDirectory().ConfigureAwait(false);

            Info("requesting certificate");

            var request = new CertificateRequest {Csr = csr.Base64UrlEncoded()};
            var response = await PostAsync<CertificateResponse>(directory.NewCertificate, request).ConfigureAwait(false);            

            Verbose($"location: {response.Location}");            

            return response;
        }

        private async Task<TResult> GetAsync<TResult>(Uri uri) where TResult : class
        {
            return await SendAsync<TResult>(HttpMethod.Get, uri, null).ConfigureAwait(false);
        }

        private async Task<TResult> PostAsync<TResult>(Uri uri, object message) where TResult : class
        {
            return await SendAsync<TResult>(HttpMethod.Post, uri, message).ConfigureAwait(false);
        }

        private async Task<TResult> SendAsync<TResult>(HttpMethod method, Uri uri, object message) where TResult : class
        {
            Verbose($"{method} {uri} {message?.GetType()}");
            var nonceHeader = new AcmeHeader { Nonce = nonce };
            Verbose($"sending nonce {nonce}");

            HttpContent content = null;
            if (message != null)
            {
                var encodedMessage = jws.Encode(message, nonceHeader);
                var json = JsonConvert.SerializeObject(encodedMessage, new JsonSerializerSettings() { NullValueHandling = NullValueHandling.Ignore, Formatting = Formatting.Indented });
                content = new StringContent(json, Encoding.UTF8, "application/json");
            }
            
            var request = new HttpRequestMessage(method, uri)
            {
                Content = content
            };

            var response = await client.SendAsync(request).ConfigureAwait(false);
            
            Verbose($"response status: {(int)response.StatusCode} {response.ReasonPhrase}");
            
            RememberNonce(response);
            

            if (response.Content.Headers.ContentType.MediaType == "application/problem+json")
            {
                var problemJson = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                var problem = JsonConvert.DeserializeObject<Problem>(problemJson);
                Verbose($"error response from server: {problem.Type}: {problem.Detail}");
                throw new AcmeException(problem, response);
            }

            if (typeof(TResult) == typeof(CertificateResponse) && response.Content.Headers.ContentType.MediaType == "application/pkix-cert")
            {                
                var certificateBytes = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                var certificateResponse = new CertificateResponse() {Certificate = certificateBytes};
                GetHeaderValues(response, certificateResponse);
                return certificateResponse as TResult;
            }

            var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            var responseObj = JsonConvert.DeserializeObject<TResult>(responseBody);

            GetHeaderValues(response, responseObj);

            return responseObj;
        }

        private static void GetHeaderValues<TResult>(HttpResponseMessage response, TResult responseContent)
        {
            var properties =
                typeof (TResult).GetProperties(BindingFlags.Public | (BindingFlags) 8192 /*BindingFlags.SetProperty*/ | BindingFlags.Instance)
                    .Where(p => p.PropertyType == typeof (string))
                    .ToDictionary(p => p.Name, p => p);
            foreach (var header in response.Headers)
            {
                if (properties.ContainsKey(header.Key) && header.Value.Count() == 1)
                {                    
                    properties[header.Key].SetValue(responseContent, header.Value.First());                    
                }

                if (header.Key == "Link")
                {
                    foreach (var link in header.Value)
                    {
                        var parts = link.Split(';');
                        if (parts.Length != 2)
                        {
                            continue;
                        }
                        if (parts[1] == "rel=\"terms-of-service\"" && properties.ContainsKey("Agreement"))
                        {
                            properties["Agreement"].SetValue(responseContent, parts[0].Substring(1, parts[0].Length - 2));
                        }
                    }
                }
            }
        }
    }
}