/*
 * This library implements all functions of Latch API.
 * Copyright (C) 2013 Eleven Paths

 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "latch.h"

namespace Latch
{

	typedef struct curl_response_buffer {
		char *buffer;
		size_t size;
	} curl_response_buffer;

	/*
	 * Function to handle stuff from HTTP response.
	 *
	 * @param buf- Raw buffer from libcurl.
	 * @param len- number of indexes
	 * @param size- size of each index
	 * @param userdata- any extra user data needed
	 * @return Number of bytes actually handled. If different from len * size, curl will throw an error
	 */
	static size_t writeFn(void* buf, size_t len, size_t size, void* userdata) {
		size_t realsize = len * size;
		curl_response_buffer *response = (curl_response_buffer*)userdata;

		response->buffer = (char *)realloc(response->buffer, response->size + realsize + 1);

		memcpy(&(response->buffer[response->size]), buf, realsize);
		response->size += realsize;
		response->buffer[response->size] = '\0';

		return realsize;
	}

	static char encoding_table[] = {  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
		'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
		'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };
	static int mod_table[] = { 0, 2, 1 };

	/*
	* Function to encode a string in Base64 format
	*
	* @param input- string to encode
	* @param length- string length
	* @return encoded string in Base64 format
	*/
	char* base64encode(const unsigned char *data, int input_length) {
		int output_length = 4 * ((input_length + 2) / 3);

		char *encoded_data = (char*)malloc(output_length + 1);
		if (encoded_data == NULL) return NULL;

		for (int i = 0, j = 0; i < input_length;) {
			INT32 octet_a = i < input_length ? (unsigned char)data[i++] : 0;
			INT32 octet_b = i < input_length ? (unsigned char)data[i++] : 0;
			INT32 octet_c = i < input_length ? (unsigned char)data[i++] : 0;

			INT32 triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

			encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
			encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
			encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
			encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
		}

		for (int i = 0; i < mod_table[input_length % 3]; i++) {
			encoded_data[output_length - 1 - i] = '=';
		}

		encoded_data[output_length] = 0;

		return encoded_data;
	}


	/*
	* Function to calculate the HMAC hash (SHA1) of a string. Returns a Base64 value of the hash
	*
	* @param pSecretKey- secret key
	* @param pData- original data to calculate the HMAC
	* @return HMAC in Base64 format
	*/
	char* sign_data(const char* pSecretKey, const char* pData) {
		unsigned char* digest;

		digest = HMAC(EVP_sha1(), pSecretKey, (int)strlen(pSecretKey), (unsigned char*)pData, strlen(pData), NULL, NULL);

		return base64encode(digest, 20);
	}

	int Timeout = LATCH_TIMEOUT_SECONDS;
	const char* AppId;
	const char* SecretKey;
	const char* Host = "https://latch.elevenpaths.com";
	const char* Proxy = NULL;
	int	ProxyPort = 80;
	const char* ProxyCredentials = NULL;
	const char* tlsCAFile = NULL;
	const char* tlsCAPath = NULL;

	void init(const char* pAppId, const char* pSecretKey) {
		AppId = pAppId;
		SecretKey = pSecretKey;
	}

	void setHost(const char* pHost){
		Host = pHost;
	}

	/*
	 * Enable using a Proxy to connect to Latch Server
	 */
	void setProxy(const char* pProxy)
	{
		Proxy = pProxy;
	}

	void setProxyPort(const int pProxyPort)
	{
		ProxyPort = pProxyPort;
	}

	void setProxyCredentials(const char* pProxyCredentials)
	{
		ProxyCredentials = pProxyCredentials;
	}

	void setTimeout(const int pTimeout)
	{
		Timeout = pTimeout;
	}

	void setTLSCAFile(const char* pTLSCAFile)
	{
		tlsCAFile = pTLSCAFile;
	}
	
	void setTLSCAPath(const char* pTLSCAPath)
	{
		tlsCAPath = pTLSCAPath;
	}

	void authenticationHeaders(const char* pHTTPMethod, const char* pQueryString, char* pHeaders[]) {
		char *authHeader, *dateHeader, *uaHeader, *stringToSign, *b64hash;
		char utc[20];
		time_t timer;
		struct tm tm_info;
		size_t len;
		
		memset(utc, 0, sizeof(utc));

		time(&timer);
		gmtime_s(&tm_info, &timer);
		strftime(utc, 20, UTC_STRING_FORMAT, &tm_info);

		uaHeader = "";
#ifdef ActiveDirectoryVersion
		len = strlen(USER_AGENT_HEADER_NAME) + strlen(WINDOWS_AUTH_PLUGIN_UA) + 2;
		uaHeader = (char *)malloc(len);
		_snprintf_s(uaHeader, len, _TRUNCATE, "%s:%s", USER_AGENT_HEADER_NAME, WINDOWS_AUTH_PLUGIN_UA);
#endif

		len = strlen(pHTTPMethod) + strlen(utc) + 4 + strlen(uaHeader) + strlen(pQueryString);
		stringToSign = (char *)malloc(len);
		_snprintf_s(stringToSign, len, _TRUNCATE, "%s\n%s\n%s\n%s", pHTTPMethod, utc, uaHeader, pQueryString);

		b64hash = sign_data(SecretKey, stringToSign);

		len = strlen(AUTHORIZATION_HEADER_NAME) + strlen(AUTHORIZATION_METHOD) + strlen(AppId) + strlen(b64hash) + 5;
		authHeader = (char *)malloc(len);
		_snprintf_s(authHeader, len, _TRUNCATE, "%s: %s %s %s", AUTHORIZATION_HEADER_NAME, AUTHORIZATION_METHOD, AppId, b64hash);

		len = strlen(DATE_HEADER_NAME) + 3 + strlen(utc);
		dateHeader = (char *)malloc(len);
		_snprintf_s(dateHeader, len, _TRUNCATE, "%s: %s", DATE_HEADER_NAME, utc);

		pHeaders[0] = authHeader;
		pHeaders[1] = dateHeader;
#ifdef ActiveDirectoryVersion
		pHeaders[2] = uaHeader;
#endif

		free(stringToSign);
		free(b64hash);
	}

	/*
	* Perform a GET request to the specified URL of the Latch API
	* @param pUrl- requested URL including host
	*/
	char* http_get_proxy(const char* pUrl) {
#ifdef ActiveDirectoryVersion
		char* headers[3];
#else
		char* headers[2];
#endif
		curl_response_buffer response;
		char error_message[CURL_ERROR_SIZE];
		CURL* pCurl = curl_easy_init();
		int res = -1;
		int i = 0;
		struct curl_slist* chunk = NULL;
		char* hostAndUrl;
		size_t len;

		memset(error_message, 0, CURL_ERROR_SIZE);

		if (!pCurl) {
			return NULL;
		}

		response.buffer = (char *)malloc(1 * sizeof(char));
		response.size = 0;
		response.buffer[response.size] = '\0';

		authenticationHeaders("GET", pUrl, headers);
		for (i = 0; i < (sizeof(headers) / sizeof(char*)); i++) {
			chunk = curl_slist_append(chunk, headers[i]);
			free(headers[i]);
		}

		len = strlen(Host) + strlen(pUrl) + 1;
		hostAndUrl = (char *)malloc(len);
		strcpy_s(hostAndUrl, len, Host);
		strcat_s(hostAndUrl, len, pUrl);

		curl_easy_setopt(pCurl, CURLOPT_URL, hostAndUrl);
		curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, chunk);
		curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, writeFn);
		curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, &response);
		curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1); // we don't care about progress
		curl_easy_setopt(pCurl, CURLOPT_FAILONERROR, 1);

		if (Proxy != NULL) {
			curl_easy_setopt(pCurl, CURLOPT_PROXYTYPE, 'HTTP');
			curl_easy_setopt(pCurl, CURLOPT_PROXY, Proxy);
			curl_easy_setopt(pCurl, CURLOPT_PROXYPORT, ProxyPort);

			if (ProxyCredentials != NULL) {
				curl_easy_setopt(pCurl, CURLOPT_PROXYUSERPWD, ProxyCredentials);
			}
		}

		// we don't want to leave our user waiting at the login prompt forever
		curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, Timeout);

		// SSL needs 16k of random stuff. We'll give it some space in RAM.
		curl_easy_setopt(pCurl, CURLOPT_RANDOM_FILE, "/dev/urandom");
		curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 1);
		curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2);
		curl_easy_setopt(pCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

		// error message when curl_easy_perform return non-zero
		curl_easy_setopt(pCurl, CURLOPT_ERRORBUFFER, error_message);

		if (tlsCAFile != NULL) {
			curl_easy_setopt(pCurl, CURLOPT_CAINFO, tlsCAFile);
			curl_easy_setopt(pCurl, CURLOPT_CAPATH, NULL);
		}
		else if (tlsCAPath != NULL) {
			curl_easy_setopt(pCurl, CURLOPT_CAINFO, NULL);
			curl_easy_setopt(pCurl, CURLOPT_CAPATH, tlsCAPath);
		}
		
		// synchronous, but we don't really care
		res = curl_easy_perform(pCurl);

		curl_easy_cleanup(pCurl);
		curl_slist_free_all(chunk);

		//printf("ERROR: %s\n", error_message);

		free(hostAndUrl);

		if (res != CURLE_OK) {
			free(response.buffer);
			return NULL;
		}
		else {
			return response.buffer;
		}
	}

	char* pairWithId(const char* pAccountId) {
		char* response = NULL;
		size_t len = strlen(API_PAIR_WITH_ID_URL) + strlen(pAccountId) + 2;
		char* url = (char *)malloc(len * sizeof(char));

		if (url != NULL) {
			_snprintf_s(url, len, _TRUNCATE, "%s/%s", API_PAIR_WITH_ID_URL, pAccountId);
			response = http_get_proxy(url);
			free(url);
		}
		return response;
	}

	char* pair(const char* pToken) {
		char* response = NULL;
		size_t len = strlen(API_PAIR_URL) + strlen(pToken) + 2;
		char* url = (char *)malloc(len * sizeof(char));

		if (url != NULL) {
			_snprintf_s(url, len, _TRUNCATE, "%s/%s", API_PAIR_URL, pToken);
			response = http_get_proxy(url);
			free(url);
		}
		return response;
	}

	char* status(const char* pAccountId) {
		char* response = NULL;
		size_t len = strlen(API_CHECK_STATUS_URL) + strlen(pAccountId) + 2;
		char* url = (char *)malloc(len * sizeof(char));

		if (url != NULL) {
			_snprintf_s(url, len, _TRUNCATE, "%s/%s", API_CHECK_STATUS_URL, pAccountId);
			response = http_get_proxy(url);
			free(url);
		}
		return response;
	}

	char* operationStatus(const char* pAccountId, const char* pOperationId) {
		char* response = NULL;
		size_t len = strlen(API_CHECK_STATUS_URL) + strlen(pAccountId) + strlen(pOperationId) + 6;
		char* url = (char *)malloc(len * sizeof(char));

		if (url != NULL) {
			_snprintf_s(url, len, _TRUNCATE, "%s/%s/op/%s", API_CHECK_STATUS_URL, pAccountId, pOperationId);
			response = http_get_proxy(url);
			free(url);
		}
		return response;
	}

	char* unpair(const char* pAccountId) {
		char* response = NULL;
		size_t len = strlen(API_UNPAIR_URL) + strlen(pAccountId) + 2;
		char* url = (char *)malloc(len * sizeof(char));

		if (url != NULL) {
			_snprintf_s(url, len, _TRUNCATE, "%s/%s", API_UNPAIR_URL, pAccountId);
			response = http_get_proxy(url);
			free(url);
		}
		return response;
	}
}

