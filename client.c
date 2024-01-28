#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define PORT "3490" // the port client will be connecting to 

#define MAXDATASIZE 100 // max number of bytes we can get at once 

#define MAX_HOST_LEN 255
#define MAX_PATH_LEN 1024

// Structure to hold the URL components
typedef struct {
    char protocol[6]; // We will only support HTTP, so 6 chars (+ null terminator) is enough
    char hostname[MAX_HOST_LEN];
    char port[6]; // A port number can be up to 5 digits long
    char path[MAX_PATH_LEN];
} ParsedUrl;

// Function to parse the URL
int parse_url(const char *url, ParsedUrl *parsed_url) {
    // Initialize the structure with zeros
    memset(parsed_url, 0, sizeof(ParsedUrl));

    // Copy the URL into a local buffer that we can modify
    char url_copy[MAX_HOST_LEN + MAX_PATH_LEN];
    strncpy(url_copy, url, sizeof(url_copy));
    url_copy[sizeof(url_copy) - 1] = '\0'; // Ensure null-termination

    char *protocol_ptr = strstr(url_copy, "://");
    if (protocol_ptr == NULL) {
        fprintf(stderr, "Error: URL does not contain '://'\n");
        return -1;
    }
    
    // Extract the protocol
    strncpy(parsed_url->protocol, url_copy, protocol_ptr - url_copy);
    parsed_url->protocol[protocol_ptr - url_copy] = '\0';

    // Check if the protocol is HTTP
    if (strcmp(parsed_url->protocol, "http") != 0) {
        fprintf(stderr, "Error: Only 'http' protocol is supported\n");
        return -1;
    }

    // Move past the "://"
    char *hostname_ptr = protocol_ptr + 3;
    
    // Look for the first slash after the protocol to find the end of the hostname and start of path
    char *path_ptr = strchr(hostname_ptr, '/');
    if (path_ptr) {
        // Extract the path
        strncpy(parsed_url->path, path_ptr, sizeof(parsed_url->path));
        parsed_url->path[sizeof(parsed_url->path) - 1] = '\0';
        
        // Null-terminate the hostname at the start of the path
        *path_ptr = '\0';
    } else {
        // If there's no path, set path to "/"
        strcpy(parsed_url->path, "/");
    }

    // Look for a colon in the hostname to find a port
    char *port_ptr = strchr(hostname_ptr, ':');
    if (port_ptr) {
        // Extract the port
        strncpy(parsed_url->port, port_ptr + 1, sizeof(parsed_url->port));
        parsed_url->port[sizeof(parsed_url->port) - 1] = '\0';
        
        // Null-terminate the hostname at the start of the port
        *port_ptr = '\0';
    } else {
        // If there's no port, set to default HTTP port "80"
        strcpy(parsed_url->port, "80");
    }

    // Copy the hostname into the structure
    strncpy(parsed_url->hostname, hostname_ptr, sizeof(parsed_url->hostname));
    parsed_url->hostname[sizeof(parsed_url->hostname) - 1] = '\0';

    return 0;
}

#define REQUEST_TEMPLATE "GET %s HTTP/1.1\r\n" \
                         "Host: %s\r\n" \
                         "User-Agent: CustomHTTPClientByEricLin/1.0\r\n" \
                         "Connection: close\r\n" \
                         "\r\n"

void create_get_request(const char *hostname, const char *port, const char *path, char *http_request) {
    // Ensure the request buffer is large enough for the request
    sprintf(http_request, REQUEST_TEMPLATE, path, hostname);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: http_client http://hostname[:port]/path_to_file\n");
        exit(1);
    }

    char *url = argv[1];
    char *hostname; // Extracted hostname
    char *port; // Extracted port or default to 80
    char *path; // Extracted path

	// url parsing
    ParsedUrl parsed_url;
    if (parse_url(argv[1], &parsed_url) < 0) {
        fprintf(stderr, "Error parsing URL\n");
        return 1;
    }

    printf("Protocol: %s\n", parsed_url.protocol);
    printf("Hostname: %s\n", parsed_url.hostname);
    printf("Port: %s\n", parsed_url.port);
    printf("Path: %s\n", parsed_url.path);

	char http_request[1024]; // Adjust size as needed for your request

    // Create the HTTP GET request string
    create_get_request(parsed_url.hostname, parsed_url.port, parsed_url.path, http_request);

    printf("HTTP GET Request:\n%s\n", http_request);

    return 0;

    // TODO: Establish a TCP connection to the server on the extracted or default port
    // ...

    // TODO: Form the HTTP GET request using the extracted path (and possibly hostname)
    // ...

    // TODO: Send the HTTP GET request
    // ...

    // TODO: Read the server's response
    // ...

    // TODO: Handle the server's response, including the case where the file is not found
    // ...

    // TODO: Save the response body to a file named "output" if the request was successful
    // ...

    // TODO: Close the socket
    // ...
}

