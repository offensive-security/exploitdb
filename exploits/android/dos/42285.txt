Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=1226

There are three variants of the below crash, all of which stemming from an unbound copy into a fixed size stack buffer allocated in the function ASFParser::SetMetaData, used as an argument to each of the three calls to the function unicodeToUtf_8 without checking that the output length will be less than the size of the buffer. You can see in the crashdump that the argv array has been overwritten by junk unicode output, resulting in the corrupted binary path displayed in the output.

I believe that this issue is mitigated by compiling with stack cookies, so I'm not applying the 90 day deadline to this issue since I don't think it's exploitable except as a denial-of-service.

*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
Build fingerprint: 'lge/p1_global_com/p1:6.0/MRA58K/1624210305d45:user/release-keys'
Revision: '11'
ABI: 'arm'
pid: 435, tid: 435, name: mediaserver  >>> �ు둢吟ѷἃ舄㹂慮춎䇛㾾攞䎤➹뽉龂팆顯浃桡＞￿큾略혭拴畹㿺㬭똦৿➦쎪悸ꪰ뒇᭥릧㠙���褓悀䳘牀⛕鑆ࡢ���㹇䊌⾩ʘỬ操陊ꦑ䤮峇ᇱ빌屸쒫羮죾‘궈砜톢庋_䔗蛴ᰦ꿚肁࿗砘搒깷옮豩烙켯펤傁䅥툺帰Ŧ䥎ᢘ퐢옥ꤤࠨ᪗@���Ԃ깛Ȯ댁ૃ⒨待讍ꄌ鈤䄚戬㸵Ṣ䙌䠖咂徕琣༔ৰ씊塀⏆ð厔⁀呕！谀櫰ុì⪌跔띦䳊薵結စ䌷﷌���๑髇#쀇붭
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0xff951000
    r0 ff951002  r1 f023b0ba  r2 0000100e  r3 ffffff8f
AM write failed: Broken pipe
    r4 00000792  r5 f023bfde  r6 f5f1c080  r7 efdfca69
    r8 f1282348  r9 ff94fc70  sl f1282348  fp 00000012
    ip 0000a3c6  sp ff94fc5c  lr efdf7457  pc efdf4a9a  cpsr 800f0030

backtrace:
    #00 pc 00003a9a  /system/lib/liblg_parser_asf.so (_Z14unicodeToUtf_8PhPti+85)
    #01 pc 00006453  /system/lib/liblg_parser_asf.so (_ZN9ASFParser11SetMetaDataEP15meta_descriptor+186)
    #02 pc 6b203432  <unknown>


Proof of Concept:
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42285.zip