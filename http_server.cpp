#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "log.h"
#include "utils.h"
#include "defines.h"
#include "http_request_t.h"
#include "http_bundle.h"
#include "http_server.h"

http_server::http_server(int fd_in) : fd(fd_in), request_type(static_cast<http_request_t>(-1))
{
	request_data = reinterpret_cast<unsigned char *>(malloc(HTTP_SERVER_READ_SIZE + 1));
	request_data_size = 0;
	request_type = HR_FAIL;

	char *headers_end = NULL;
	bool crlf = true;

	do
	{
		int rc = read(fd_in, &request_data[request_data_size], HTTP_SERVER_READ_SIZE);
		if (rc == -1 || rc == 0)
		{
			if (rc == -1 && errno == EINTR)
				continue;

			dolog(LOG_INFO, "HTTP: short read");
			break;
		}

		request_data_size += rc;
		request_data = reinterpret_cast<unsigned char *>(realloc(request_data, request_data_size + HTTP_SERVER_READ_SIZE + 1));

		request_data[request_data_size] = 0x00;

		headers_end = strstr(reinterpret_cast<char *>(request_data), "\r\n\r\n");
		if (!headers_end)
		{
			headers_end = strstr(reinterpret_cast<char *>(request_data), "\n\n");
			if (headers_end)
				crlf = false;
		}
	}
	while(headers_end == NULL);

	if (headers_end)
	{
		// get headers from request
		*headers_end = 0x00;

		const char *line_end = crlf ? "\r\n" : "\n";

		char **headers = NULL;
		int n_headers = 0;
		split_string(reinterpret_cast<char *>(request_data), line_end, &headers, &n_headers);

		for(int index=0; index<n_headers; index++)
			request_headers.push_back(headers[index]);

		// set request_type for GET/POST
		char **request_parts = NULL;
		int n_request_parts = 0;
		split_string(headers[0], " ", &request_parts, &n_request_parts);
		if (n_request_parts >= 1)
		{
			if (strcmp(request_parts[0], "GET") == 0)
				request_type = HR_GET;
			else if (strcmp(request_parts[0], "POST") == 0)
				request_type = HR_POST;
		}
		if (n_request_parts >= 2)
			request_url = request_parts[1];

		for(int index=0; index<n_request_parts; index++)
			free(request_parts[index]);
		free(request_parts);

		for(int index=0; index<n_headers; index++)
			free(headers[index]);
		free(headers);

		// memmove read data (if any) to front
		int headers_size = int(headers_end - reinterpret_cast<char *>(request_data)) + (crlf ? 4 : 2);
		int bytes_left = request_data_size - headers_size;
		if (bytes_left)
		{
			memmove(request_data, &request_data[headers_size], bytes_left);
			request_data_size -= headers_size;
		}
		else
		{
			request_data_size = 0;
		}
	}
}

http_server::~http_server()
{
	free(request_data);
}

http_request_t http_server::get_request_type()
{
	return request_type;
}

http_bundle * http_server::get_request()
{
	return new http_bundle(request_headers, request_data, request_data_size);
}

std::string http_server::get_request_url()
{
	return request_url;
}

bool http_server::send(const char *what)
{
	int len = strlen(what);

	// printf("> %s", what);

	return send((unsigned char *)what, len);
}

bool http_server::send(unsigned char *p, int len)
{
	if (WRITE_TO(fd, p, len, DEFAULT_COMM_TO) != len)
		return false;

	return true;
}

void http_server::send_response(int status_code, std::vector<std::string> *headers, http_bundle *response)
{
	headers -> insert(headers -> begin(), format("HTTP/1.0 %d", status_code));
	headers -> push_back("Expires: Fri, 09 Nov 2017 14:55:30 GMT");
	headers -> push_back("Cache-Control: no-cache");
	headers -> push_back("Pragma: no-cache");
	headers -> push_back(format("Content-Length: %d", response -> get_data_len()));

	bool ok = true;
	for(unsigned int index=0; index<headers -> size() && ok; index++)
		ok = send((headers -> at(index) + "\r\n").c_str());

	if (ok)
		ok = send("\r\n");

	if (ok)
		ok = send(response -> get_data(), response -> get_data_len());

	close(fd);

	fd = -1;
}
