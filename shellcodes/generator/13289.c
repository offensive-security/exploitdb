/*
______________________________________________________________________________

     ,sSSSis   ,sSSSs,   Beta v2.0 (w32).
    iS"   dP  dY"  ,SP   Encodes binary data to/from a variety of formats.
   .SP dSS"      ,sS"    Copyright (C) 2003-2005 by Berend-Jan Wever
   dS'   Sb    ,sY"      <skylined@edup.tudelft.nl>
  .SP dSSP'  sSSSSSSP    http://spaces.msn.com/members/berendjanwever
_ iS:_________________________________________________________________________

  This program is free software; you can redistribute it and/or modify it under
  the terms of the GNU General Public License version 2, 1991 as published by
  the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
  details.

  A copy of the GNU General Public License can be found at:
    http://www.gnu.org/licenses/gpl.html
  or you can write to:
    Free Software Foundation, Inc.
    59 Temple Place - Suite 330
    Boston, MA  02111-1307
    USA.
*/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <windows.h>

#define MAX_BUFFER_SIZE 0x1000
#define DEFAULT_PAD_BYTE 0x90
#define MAX_MARKER_SIZE 0x10
#define bool char
#define true 1
#define false 0

char* hex = "0123456789abcdef";

void version(void) {
    printf(
        "______________________________________________________________________________\n"
        "\n"
        "     ,sSSSis   ,sSSSs,   Beta v2.0.\n"
        "    iS\"   dP  dY\"  ,SP   Encodes binary data to/from a variety of formats.\n"
        "   .SP dSS\"      ,sS\"    Copyright (C) 2003-2005 by Berend-Jan Wever\n"
        "   dS'   Sb    ,sY\"      <skylined@edup.tudelft.nl>\n"
        "  .SP dSSP'  sSSSSSSP    http://spaces.msn.com/members/berendjanwever\n"
        "_ iS:_________________________________________________________________________\n"
        "\n"
    );
  return;
}
void help(void) {
    printf(
        "Beta was developed to convert raw binary shellcode into text that can be\n"
        "used in exploit source-code. It can convert raw binary data to a large\n"
        "number of encodings.\n"
		"\n"
        "  Usage: BETA [options] [input file name]\n"
		"\n"
        "  input file name           Read input from the given file. By default BETA\n"
        "                            reads input from stdin.\n"
		"\n"
        "General options:\n"
        "  --help                    Display this help and exit\n"
        "  --version                 Output version information and exit\n"
        "  --verbose                 Displays additional information.\n"
        "  --pause                   Wait for keypress before exiting.\n"
		"\n"
		"Encoding options: (default = AA BB CC ...)\n"
        "  \\x                        \\xAA\\xBB\\xCC ...\n"
        "  0x                        0xAA 0xBB 0xCC ...\n"
        "  %%                         %%AA%%BB%%CC...\n"
        "  #                         &#111;&#222;&#33;...\n"
        "  %%u                        %%uBBAA%%uDDCC...\n"
        "  --noencode                Don't encode (only do checks).\n"
		"\n"
        "Layout options: (default = none)\n"
        "  --chars/line=X            Output a new line after every X encoded bytes.\n"
        "  --quotes                  Wrap output in quotes. Only usefull in combination\n"
        "                            with chars/line argument.\n"
        "  --quotesplus              Wrap output in quotes and add a '+' at the end\n"
        "                            of each line. Only usefull in combination with\n"
        "                            chars/line argument.\n"
        "  --spaces                  Seperate encoding entities by spaces.\n"
        "  --commas                  Seperate encoding entities by commas and spaces.\n"
		"\n"
		"Additional options:\n"
		"  --padbyte=AA              When using a multibyte encoding (e.g. %%uXXXX)\n"
		"                            the data might need some padding. The given byte\n"
		"                            will be used, the default value is %02x.\n"
		"  --badbytes[=AA[,BB[...]]] Check the input for presence of the given char-\n"
		"                            acters and report where they are found. You can\n"
		"                            supply a comma seperated list of hexadecimal\n"
		"                            character codes and the keywords \"alpha\" and\n"
		"                            \"print\" (to check for the presence of nonalpha-\n"
		"                            numeric or non-printable characters). If no char-\n"
		"                            acters are supplied, the input will be checked for\n"
		"                            the presence of 00, 0A and 0D. \n"
        "  --marker[=AA[,BB[...]]]   The input contains both garbage and data. The data\n"
        "                            is wrapped by the marker bytes, everything before\n"
        "                            the first set and after the last set of marker\n"
        "                            bytes will be ignored. If no marker bytes are\n"
        "                            supplied, \"CC CC CC\" (3xInt3) will be used.\n"
        "                            You can supply up to %d bytes as marker.\n",
        DEFAULT_PAD_BYTE, MAX_MARKER_SIZE
    );
  return;
}

// Find a set of bytes in another set of bytes
char* find_bytes(char* haystack, int haystack_length, char* needle, int needle_length) {
	int needle_start = -1, needle_checked = 1;
	do {
		if (haystack[needle_start+needle_checked] == needle[needle_checked])
			// Yes, bytes match, check next byte of needle
			needle_checked++;
		else {
			// No, no match, check next byte of haystack
			needle_start++;
			needle_checked = 0;
		}
		if (needle_start + needle_length > haystack_length)
			// Not found.
			return 0;
	} while (needle_checked != needle_length);
	// Found!
	return haystack + needle_start;
}

int main(int argc, char** argv, char** envp) {

	// This will contain the input data
	char* buffer;
	int buffer_length = 0;

	// This will contain the marker
	char marker[MAX_MARKER_SIZE];
	int marker_length = 0;

	// This will keep track of all "bad" bytes
	char char_is_bad[0x100];
    for (int i = 0; i < sizeof(char_is_bad)/sizeof(*char_is_bad); i++)
    	char_is_bad[i] = false;

	// These will store some values supplied by command line arguments
	bool switch_verbose = false, switch_encode = true, switch_pause = false;
	char pad_byte = DEFAULT_PAD_BYTE;
    int chars_per_line = -1;
    char *input_filename = 0;
    char *line_header = "", *line_footer = "\n", *footer = "\n";
    char *bytes_format = "%02X", *byte_seperator = "";
    int bytes = 1;

	//--------------------------------------------------------------------------
	// Read and handle arguments
    for (int argn = 1; argn < argc; argn++) {
		//--help ---------------------------------------------------------------
    	if (stricmp(argv[argn], "--help") == 0) {
    		version();
    		help();
			if (switch_pause) getchar();
    		exit(EXIT_SUCCESS);
		//--version ------------------------------------------------------------
    	} else if (stricmp(argv[argn], "--version") == 0) {
    		version();
			if (switch_pause) getchar();
    		exit(EXIT_SUCCESS);
		//--verbose ------------------------------------------------------------
    	} else if (stricmp(argv[argn], "--verbose") == 0) {
    		switch_verbose = true;
		//--noencode -----------------------------------------------------------
    	} else if (stricmp(argv[argn], "--noencode") == 0) {
    		switch_encode = false;
		//--noencode -----------------------------------------------------------
    	} else if (stricmp(argv[argn], "--pause") == 0) {
    		switch_pause = true;
		//--chars/line= --------------------------------------------------------
	    } else if (strnicmp(argv[argn], "--chars/line=", 13)==0) {
	    	if ((chars_per_line = strtol(&(argv[argn][13]), NULL, 10)) < 1) {
	    		printf("Illegal number of characters per line: \"%s\".\n", &(argv[argn][13]));
	    		if (switch_pause) getchar();
	    		exit(EXIT_FAILURE);
	    	}
		//--layout options -----------------------------------------------------
	    } else if (strcmp(argv[argn], "--quote") == 0 || strcmp(argv[argn], "--quotes") == 0) {
	        line_header = "\"";
	        line_footer = "\"\n";
	        footer = "\"\n";
	    } else if (strcmp(argv[argn], "--quoteplus") == 0 || strcmp(argv[argn], "--quotesplus") == 0) {
	        line_header = "\"";
	        line_footer = "\" +\n";
	        footer = "\"\n";
	    } else if (strcmp(argv[argn], "--comma") == 0 || strcmp(argv[argn], "--commas") == 0) {
	        byte_seperator = ", ";
	    } else if (strcmp(argv[argn], "--space") == 0 || strcmp(argv[argn], "--spaces") == 0) {
	        byte_seperator = " ";
		//--encoding options ---------------------------------------------------
	    } else if (stricmp(argv[argn], "\\x")==0) {
	    	bytes_format = "\\x%02X";
	    } else if (stricmp(argv[argn], "0x")==0) {
	    	bytes_format = "0x%02X";
	    } else if (stricmp(argv[argn], "#")==0) {
	    	bytes_format = "&#%d;";
	    } else if (stricmp(argv[argn], "%")==0) {
	    	bytes_format = "%%%02X";
	    } else if (stricmp(argv[argn], "%u")==0) {
	    	bytes_format = "%%u%04X";
	    	bytes = 2;
		//--padbyte ------------------------------------------------------------
	    } else if (strnicmp(argv[argn], "--padbyte=", 10) == 0) {
	    	char* next_xarg;
			pad_byte = strtol(&(argv[argn][10]), &next_xarg, 0x10);
			if ((pad_byte & 0xFF) != pad_byte) {
				printf("Incorrect value in padbyte argument: \"%s\".\n", &(argv[argn][11]));
				printf("  Value cannot be converted to a byte ");
				for (int i = 0; i < strlen(&(argv[argn][10])); i++)
					printf("^");
				printf("\n");
				if (switch_pause) getchar();
	    		exit(EXIT_FAILURE);
			}
			if (next_xarg == &(argv[argn][10])) {
				printf("Incorrect byte encoding in padbyte argument: \"%s\".\n", &(argv[argn][10]));
				if (switch_pause) getchar();
	    		exit(EXIT_FAILURE);
			}
		//--badbytes -----------------------------------------------------------
		} else if (stricmp(argv[argn], "--badbytes") == 0) {
			char_is_bad[0x0] = true;
			char_is_bad[0xA] = true;
			char_is_bad[0xD] = true;
		//--badbytes=XX,XX,... -------------------------------------------------
	    } else if (strnicmp(argv[argn], "--badbytes=", 11) == 0) {
			char* xarg = &(argv[argn][11]);
			while (strlen(xarg) > 0) {
				if (strnicmp(xarg, "alpha", 5) == 0) {
					for (int i = 0; i < 0x100; i++) {
						if (!isalnum(i)) char_is_bad[i] = true;
					}
					xarg += 5;
				} else if (strnicmp(xarg, "print", 5) == 0) {
					for (int i = 0; i < 0x100; i++) {
						if (!isprint(i)) char_is_bad[i] = true;
					}
					xarg += 5;
				} else {
					char* next_xarg;
					int decoded = strtol(xarg, &next_xarg, 0x10);
					if ((decoded & 0xFF) != decoded) {
						printf("Incorrect value in badbytes argument: \"%s\".\n", &(argv[argn][11]));
						for (char* i = &(argv[argn][9]); i < xarg; i++)
							printf(" ");
						printf(" Value cannot be converted to a byte ");
						for (char* i = xarg; i < next_xarg; i++)
							printf("^");
						printf("\n");
						if (switch_pause) getchar();
			    		exit(EXIT_FAILURE);
					}
					if (next_xarg == xarg) {
						printf("Incorrect byte encoding in badbytes argument: \"%s\".\n", &(argv[argn][11]));
						for (char* i = &(argv[argn][11]); i < xarg; i++)
							printf(" ");
						printf("                    Character '%c' not expected ^\n", *xarg);
						if (switch_pause) getchar();
			    		exit(EXIT_FAILURE);
					}

					char_is_bad[decoded] = true;
					xarg = next_xarg;
				}
				if (*xarg == ',') xarg++;
			}
		//--marker -------------------------------------------------------------
	    } else if (stricmp(argv[argn], "--marker")==0) {
	        marker_length = 3;
	        for (int i = 0; i < marker_length; i++) marker[i] = 0xCC;
		//--marker= ------------------------------------------------------------
	    } else if (strnicmp(argv[argn], "--marker=", 9)==0) {
			char* xarg = &(argv[argn][9]);
			while (strlen(xarg) > 0) {
				if (marker_length == MAX_MARKER_SIZE) {
					printf("Given marker is too large, the maximum size is %d characters.\n", MAX_MARKER_SIZE);
					if (switch_pause) getchar();
		    		exit(EXIT_FAILURE);
				}
				char* next_xarg;
				int decoded = strtol(xarg, &next_xarg, 0x10);
				if ((decoded & 0xFF) != decoded) {
					printf("Incorrect value in marker argument: \"%s\".\n", &(argv[argn][9]));
					for (char* i = &(argv[argn][9]); i < xarg; i++)
						printf(" ");
					printf(" Value cannot be converted to a byte ");
					for (char* i = xarg; i < next_xarg; i++)
						printf("^");
					printf("\n");
					if (switch_pause) getchar();
		    		exit(EXIT_FAILURE);
				}
				marker[marker_length] = decoded;
				marker_length++;
				if (next_xarg == xarg) {
					printf("Incorrect byte encoding in marker argument: \"%s\".\n", &(argv[argn][9]));
					for (char* i = &(argv[argn][9]); i < xarg; i++)
						printf(" ");
					printf("                  Character '%c' not expected ^\n", *xarg);
					if (switch_pause) getchar();
		    		exit(EXIT_FAILURE);
				}
				xarg = next_xarg;
				if (*xarg == ',') xarg ++;
			}
	    } else {
		//--input filename -----------------------------------------------------
	    	if (input_filename != 0) {
	    		printf(
	    			"Two arguments are assumed to be file names, only one was expected:\n"
	    			"\"%s\" and \"%s\"\n",
	    			input_filename, argv[argn]
	    		);
	    		if (switch_pause) getchar();
	    		exit(EXIT_FAILURE);
	    	}
	    	input_filename = argv[argn];
    	}
    }

	if (switch_verbose) version();

	if (input_filename == 0) {
		// Read from STDIN -----------------------------------------------------
		buffer = malloc(MAX_BUFFER_SIZE);
		if (buffer == 0) {
			printf("- Cannot allocate %d bytes of memory for input buffer.\n", MAX_BUFFER_SIZE);
			if (switch_pause) getchar();
    		exit(EXIT_FAILURE);
		}
		if (switch_verbose) printf("  Input _______________: STDIN, reading...");
		while (buffer_length < MAX_BUFFER_SIZE && (buffer[buffer_length] = getchar()) != EOF) buffer_length++;
		if (switch_verbose) {
			if (buffer_length == MAX_BUFFER_SIZE)
				printf("\r  Input _______________: STDIN, %d bytes (maximum size for input data).\n", buffer_length);
			else
				printf("\r  Input _______________: STDIN, %d bytes.\n", buffer_length);
		}
	} else {
		// Read from file ------------------------------------------------------
		int input_filedescriptor = 0;
		if ((input_filedescriptor = open(input_filename, O_RDONLY | O_BINARY, 0)) == 0) {
			printf("- Cannot open file \"%s\".\n", input_filename);
			if (switch_pause) getchar();
    		exit(EXIT_FAILURE);
		}
		if ((buffer_length = lseek(input_filedescriptor, 0, SEEK_END)) == -1) {
			printf("- Cannot find end of file \"%s\".\n", input_filename);
			if (switch_pause) getchar();
    		exit(EXIT_FAILURE);
		}
		if (buffer_length == 0) {
			printf("- File \"%s\" is empty.\n", input_filename);
			if (switch_pause) getchar();
    		exit(EXIT_FAILURE);
		}
		if (lseek(input_filedescriptor, 0, SEEK_SET) == -1) {
			printf("- Cannot find start of file \"%s\".\n", input_filename);
			if (switch_pause) getchar();
    		exit(EXIT_FAILURE);
		}
		if (switch_verbose) printf("  Input file __________: \"%s\", %d bytes.\n", input_filename, buffer_length);
		if ((buffer = malloc(buffer_length)) == 0) {
			printf("- Cannot allocate %d bytes of memory for input buffer.\n", buffer_length);
			if (switch_pause) getchar();
    		exit(EXIT_FAILURE);
		}
		int bytes_read_total = 0;
		while (bytes_read_total < buffer_length) {
			int bytes_read = read(input_filedescriptor, buffer+bytes_read_total, buffer_length-bytes_read_total);
			if (bytes_read == -1) {
				printf("- Cannot read from file \"%s\".\n", input_filename);
				if (switch_pause) getchar();
	    		exit(EXIT_FAILURE);
			}
			if (bytes_read == 0) {
				printf("- Cannot read more then %d bytes of file \"%s\".\n", bytes_read_total, input_filename);
				buffer_length = bytes_read_total;
				if (switch_pause) getchar();
	    		exit(EXIT_FAILURE);
			}
			bytes_read_total += bytes_read;
		}
		close(input_filedescriptor);
	}

	// Cut out the part surrounded by the markers ------------------------------
	if (marker_length > 0) {
		if (switch_verbose) {
			printf ("  Marker bytes ________:");
			for (int i = 0; i < marker_length; i++)
				printf(" %02X", marker[i] & 0xFF);
			printf (".\n");
		}
		char *marker_start, *marker_end;
		// find the first marker
		marker_start = find_bytes(buffer, buffer_length, marker, marker_length);
		if (marker_start == 0) {
			printf("- Cannot find start marker.\n");
			if (switch_pause) getchar();
    		exit(EXIT_FAILURE);
		}
		marker_start += marker_length;
		// find the second marker
		marker_end = find_bytes(marker_start, buffer + buffer_length - marker_start, marker, marker_length);
		if (marker_end == 0) {
			printf("- Cannot find end marker.\n");
			if (switch_pause) getchar();
    		exit(EXIT_FAILURE);
		}
		if (switch_verbose) printf("  Markers found at ____: byte %d & %d.\n", (int)marker_start - (int)buffer - marker_length, (int)marker_end - (int)buffer);
		// copy data between markers to start of buffer;
		for (int i = 0; i < (int)marker_end - (int)marker_start; i++) {
			buffer[i] = marker_start[i];
		}
		buffer_length = (int)marker_end - (int)marker_start;
	}

	// Check if we have input data to encode -----------------------------------
	if (buffer_length == 0) {
		printf("- No data to encode.\n");
		if (switch_pause) getchar();
   		exit(EXIT_FAILURE);
	}
	if (switch_verbose) printf("  Data length _________: %d bytes.\n", buffer_length);

	// Add some padding --------------------------------------------------------
	if (buffer_length % bytes != 0 && switch_verbose)
		printf("* Data padding ________: %d x %02X.\n", bytes - (buffer_length  % bytes), pad_byte & 0xff);
	while(buffer_length - 1 < MAX_BUFFER_SIZE && buffer_length % bytes != 0) {
		buffer[buffer_length] = pad_byte;
		buffer_length++;
	}

	// Check for bad characters ------------------------------------------------
	for (int i = 0; i < 256; i++) {
		if (char_is_bad[i]) {
			// For each bad character
			bool this_bad_char_found = false;
			for (int j = 0; j < buffer_length; j++) {
				if (buffer[j] == i) {
					// Find all instances in the data
					if (this_bad_char_found) printf(", %d", j);
					else {
						this_bad_char_found = true;
						printf("* Bad character %02X at _: %d", i, j);
					}
				}
			}
			if (this_bad_char_found) printf(".\n");
			else if (switch_verbose)
				printf("  Bad character %02X ____: Not found.\n", i);
		}
	}
	if (switch_encode) {
		// Encode the input data ---------------------------------------------------
		if (switch_verbose) printf(
	        "\n"
	        "_ Encoded data _______________________________________________________________\n"
		);
	    int input=0, count=0;
	    // line header and footer only printed when we have a max. chars per line.
	    if (chars_per_line>0) printf("%s", line_header);
	    for (int i = 0; i < buffer_length; i+= bytes) {
			// read as many bytes as we encode and create one int from them.
	    	unsigned long input = 0;
	    	for (int j = 0; j < bytes; j++)
	    		input += (buffer[i+j] & 0xFF) << (j*8);
	        // if we've allready printed chars we might have to print seperators
	        if (i > 0) {
	            // we have to seperate bytes from each other with this:
	            printf("%s", byte_seperator);
	            // if we've allready printed enough chars on this line, end it & start a new one:
	            if (chars_per_line>0 && i % chars_per_line == 0)
	                printf("%s%s", line_footer, line_header);
	        }
	        // print the byte (with it's own header and footer) and count it.
	        printf(bytes_format, input);
	    }
	    // line header and footer only printed when we have a max. chars per line.
	    if (chars_per_line>0) printf("%s", footer);
	}
	if (switch_pause) getchar();
	exit(EXIT_SUCCESS);
}

// milw0rm.com [2005-12-16]