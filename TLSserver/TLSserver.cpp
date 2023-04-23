#pragma comment(lib, "libcurl_imp.lib")
#pragma comment(lib, "jsoncpp.lib")
#pragma comment(lib, "crypt32.lib")
#include <curl/curl.h>
#include <json/json.h>
#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <ctime>
#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)

int main(int argc, char** argv)
{
	const SSL_METHOD* method;
	SSL_CTX* ctx;

	/*--Create method and use it with context.--*/
	method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	/*--Context validation.--*/
	if (ctx == 0) {
		printf("--Context failed!--\n");
		return 1;
	}
	/*--Use server certificate.--*/
	if (SSL_CTX_use_certificate_file(ctx, "serwer.crt", SSL_FILETYPE_PEM) <= 0) {
		printf("--Server certificate failed!--\n");
		SSL_CTX_free(ctx);
		return 1;
	}
	/*--Use server private key.--*/
	if (SSL_CTX_use_PrivateKey_file(ctx, "serwer.key", SSL_FILETYPE_PEM) <= 0) {
		printf("--Client key failed!--!\n");
		SSL_CTX_free(ctx);
		return 1;
	}
	/*--Verify.--*/
	if (SSL_CTX_load_verify_locations(ctx, "ca.crt", nullptr) <= 0) {
		printf("--Verification failed!--!\n");
		SSL_CTX_free(ctx);
		return 1;
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr); //Set server verification.

	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData); //Initialize winsock.

	if (iResult != 0) {
		printf("--WSAStartup failed!--\n");
		SSL_CTX_free(ctx);
		return 1;
	}

	int socfd = socket(AF_INET, SOCK_STREAM, 0); //Creat socket.

	if (socfd == -1) {
		printf("--Socket failed!--\n");
		WSACleanup();
		SSL_CTX_free(ctx);
		return 1;
	}

	struct sockaddr_in server;
	socklen_t serverSize;
	server.sin_family = AF_INET;
	server.sin_port = htons(6666);

	if (inet_pton(AF_INET, "127.0.0.1", &(server.sin_addr)) == -1) {
		printf("--Binary conversion failed!--\n");
		closesocket(socfd);
		WSACleanup();
		SSL_CTX_free(ctx);
		return 1;
	}
	/*--Binding socket.--*/
	if (bind(socfd, (struct sockaddr*)&server, sizeof(server)) == -1) {
		printf("--Binding failed!--");
		closesocket(socfd);
		WSACleanup();
		SSL_CTX_free(ctx);
		return 1;
	}
	/*--Listening for a connection request.--*/
	if (listen(socfd, 10) == 0) {
		printf("--Waiting!--\n\n");
	} else {
		printf("--Listening failed!--\n");
		closesocket(socfd);
		WSACleanup();
		SSL_CTX_free(ctx);
		return 1;
	}

	int acceptation;
	struct sockaddr_in newSosckAddr;
	serverSize = sizeof(newSosckAddr);
	int odebranie;
	char buf[512];
	std::string msg;
	Json::Reader reader;
	Json::Value js;

	/*--A loop that keeps the server running.--*/
	while (1)
	{
		/*--Accepting an incoming connection request.--*/
		acceptation = accept(socfd, (struct sockaddr*)&newSosckAddr, &serverSize);
		if (acceptation == -1) {
			printf("--Connection rejected!--\n");
			closesocket(socfd);
			WSACleanup();
			SSL_CTX_free(ctx);
			return 1;
		}

		SSL* ssl = SSL_new(ctx); //Creating an encryption object.

		if (ssl == 0) {
			printf("--SSL failed!--\n");
			closesocket(socfd);
			WSACleanup();
			SSL_CTX_free(ctx);
			return 1;
		}
		/*--Descriptor assignment.--*/
		if (SSL_set_fd(ssl, acceptation) == 0) {
			printf("--Setting fd failed!--\n");
			closesocket(socfd);
			WSACleanup();
			SSL_free(ssl);
			SSL_CTX_free(ctx);
			return 1;
		}
		/*--Accepting an incoming SSL connection request.--*/
		if (SSL_accept(ssl) <= 0) {
			printf("--SSL connection rejected!--\n\n");
			SSL_free(ssl);
			continue;
		}
		/*--Downloading data.--*/
		while ((odebranie = SSL_read(ssl, buf, 512)) > 0) {
			msg.append(buf, odebranie);
		}

		if (odebranie == -1) {
			printf("--Downloading data failed!--\n");
		} else {
			/*--Parse JSON.--*/
			if (reader.parse(msg, js)) {

				if (js.get("temperature", false).isDouble()) {
					printf("Temperature: %.2f\n", js.get("temperature", NAN).asDouble());
				}

				printf("Time: %s", js.get("time", "null").toStyledString().c_str());

				if (js.get("weathercode", false).isInt()) {
					printf("Weathercode: %i\n", js.get("weathercode", NAN).asInt());
				}

				if (js.get("winddirection", false).isDouble()) {
					printf("Wind direction: %.2f\n", js.get("winddirection", NAN).asDouble());
				}

				if (js.get("windspeed", false).isDouble()) {
					printf("Wind speed: %.2f\n", js.get("windspeed", NAN).asDouble());
				}
				printf("\n");
			}
		}
		msg.clear();
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}
	closesocket(socfd);
	WSACleanup();
	SSL_CTX_free(ctx);
	return 0;
}