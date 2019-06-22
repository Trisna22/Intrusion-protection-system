#pragma once

#include "stdafx.h"
#include "NotificationWindow.h"
#include <atlconv.h>
#define MAX_THREADS 10

#ifndef NetworkCTRL_H
#define NetworkCTRL_H

class NetworkCTRL
{
public:
	NetworkCTRL();
	~NetworkCTRL();
private:
	HANDLE FriendlyDevThread;
	DWORD dwFriendlyDevThreadID;
	HANDLE SubRangeDevThread;
	DWORD dwSubRangeDevThreadID;
	HANDLE OnlineDevThread;
	DWORD dwOnlineDevThreadID;
public: //	All variable members for friendly devices.
	int FriendlyDevicesOnline = 0;
	string MAC_ADDRS[1000];
	string IP_ADDRS[1000];
	struct SubRangeScanInfo
	{
		string IpAddr;
		int LuckyNumber;
	};
	struct AliveInfo
	{
		string IP_ADDR;
		string MAC_ADDR;
	};
private: // All private member functions
	static void PingOneHost(string, string, string);
	static void* ScanFriendlyDevices();
	static void* ScanSubrangeDevices();
	static DWORD WINAPI ScanOneSubrangeDevice(LPVOID);
	static DWORD WINAPI AliveDevicesLoop(LPVOID);
};
	
NetworkCTRL::NetworkCTRL()
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NULL)
	{
		MessageBoxA(NULL, "WSAStartup failed!", "IPS: Error", MB_OK | MB_ICONERROR);
		return;
	}

	ofstream outfile("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::trunc | ios::beg);
	outfile.close();
	ofstream outfile2("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices.ips", ios::trunc | ios::beg);
	outfile2.close();

	/*	SCANNING POTENTIAL FRIENDLY DEVICES		*/

	FriendlyDevThread = CreateThread(NULL, 0, (unsigned long(__stdcall *)(void*))NetworkCTRL::ScanFriendlyDevices, (void*)NULL, 0, &dwFriendlyDevThreadID);
	if (!FriendlyDevThread)
	{
		MessageBoxA(NULL, "Failed to start Thread [ScanFriendlyDevices()]!", "IPS: Error", MB_OK | MB_ICONERROR);
	}

	/*	SCANNING SUBRANGE IPADDRESSES			*/

	SubRangeDevThread = CreateThread(NULL, 0, (unsigned long(__stdcall *)(void*))NetworkCTRL::ScanSubrangeDevices, (void*)NULL, 0, &dwSubRangeDevThreadID);
	if (!SubRangeDevThread)
	{
		MessageBoxA(NULL, "Failed to start Thread [ScanSubRangeDevices()]!", "IPS: Error", MB_OK | MB_ICONERROR);
	}

}
NetworkCTRL::~NetworkCTRL()
{
	TerminateThread(FriendlyDevThread, 0);
	TerminateThread(SubRangeDevThread, 0);
	WSACleanup();
}
void NetworkCTRL::PingOneHost(string MAC_ADDR, string TARGET_IP, string FRIENDLY_NAME)
{
	//	ICMP Echo and retrieve IP	
	unsigned long IP = INADDR_NONE;
	DWORD dwRetVal = 0;
	char SendData[32] = "abcdefghijklmnopqrstuvwxyz";
	void* ReplyBuffer = NULL;
	DWORD ReplySize = 0;
	HANDLE IcmpFile = IcmpCreateFile();
	if (IcmpFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "Failed to create ICMP File!", "IPS: Error", MB_OK | MB_ICONERROR);
		return;
	}

	IP = stoul(TARGET_IP.c_str(), nullptr, 0);
	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
	ReplyBuffer = malloc(ReplySize);
	if (ReplyBuffer == NULL)
	{
		MessageBoxA(NULL, "Failed to allocate memory!", "IPS: Error", MB_OK | MB_ICONERROR);
		return;
	}

	IPAddr s = inet_addr(TARGET_IP.c_str());
	dwRetVal = IcmpSendEcho(IcmpFile, s, SendData, sizeof(SendData),
		NULL, ReplyBuffer, ReplySize, 1000);

	if (dwRetVal != NULL)
	{
		ULONG MacAddr[2];
		ULONG PhysAddrlen = 6;
		BYTE *bPhysAddr;
		memset(&MacAddr, 0xff, sizeof(MacAddr));
		IPAddr SrcIp = 0;
		dwRetVal = SendARP(s, SrcIp, &MacAddr, &PhysAddrlen);
		if (dwRetVal == NO_ERROR)
		{
			bPhysAddr = (BYTE *)&MacAddr;
			if (PhysAddrlen)
			{
				string addr;
				for (int i = 0; i < (int)PhysAddrlen; i++)
				{
					if (i == (PhysAddrlen - 1))
					{
						stringstream ss;
						ss << std::hex << (int)bPhysAddr[i];
						string part = ss.str();
						if (part.length() == 1)
						{
							part = "0" + part;
						}
						addr = addr + part;
					}
					else
					{
						stringstream ss;
						ss << std::hex << (int)bPhysAddr[i] << ":";		
						string part = ss.str();
						if (part.length() == 2)
						{
							part = "0" + part;
						}
						addr = addr + part;
					}
				}
				transform(addr.begin(), addr.end(), addr.begin(), ::toupper);

				//	Check if the MAC Address is similar
				if (MAC_ADDR == addr)
				{
					BOOL ALREADY_EXI = FALSE;
					//	Check if the string isn't already in the online devices list
					ifstream iff("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::beg);
					if (!iff)
					{
						MessageBoxA(NULL, "Failed to open Online-Devices.ips file! ALREADY_EXI", "IPS: Error", MB_OK | MB_ICONERROR);
						return;
					}
					else
					{
						string line;
						while (getline(iff, line))
						{
							if (line.find(MAC_ADDR) != string::npos)
							{
								//	Already exists in Online-Devices list
								ALREADY_EXI = TRUE;	
								break;
							}
						}
					}
					iff.close();
					if (ALREADY_EXI == TRUE)
						return;
					ofstream off("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::app);
					if (!off)
					{
						MessageBoxA(NULL, "Failed to open Online-Devices,.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
						return;
					}
					off << MAC_ADDR << " - " << TARGET_IP << " - " << FRIENDLY_NAME << endl; //	Add friendly-nickname
					off.close();

					//	THREAD FOR CHECKING IF DEVICE IS STILL ALIVE
					AliveInfo *info = new AliveInfo();
					info->IP_ADDR = TARGET_IP;
					info->MAC_ADDR = MAC_ADDR;
					CreateThread(NULL, 0, &AliveDevicesLoop, (LPVOID)info, NULL, NULL);
				}
			}
		}
	}
	else if (WSAGetLastError() == IP_STATUS_BASE + IP_REQ_TIMED_OUT || WSAGetLastError() == 11010)
	{
		//MessageBoxA(NULL, "Ping timed-out", "Error", MB_OK);
	}
	else if (dwRetVal == IP_STATUS_BASE + IP_REQ_TIMED_OUT || dwRetVal == 11010)
	{
		//MessageBoxA(NULL, "Ping timed-out", "Error", MB_OK);
	}
	else
	{
		stringstream ss;
		ss << "Ping failed: " << WSAGetLastError() << " Ret value: " << dwRetVal;
		MessageBoxA(NULL, ss.str().c_str(), "Error", MB_OK);
	}
}
void *NetworkCTRL::ScanFriendlyDevices()
{
	while (true)
	{
		ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Friendly-Devices.ips", ios::beg);
		if (infile.is_open() == FALSE)
		{
			MessageBoxA(NULL, "Failed to open file!", "IPS: Error", MB_OK | MB_ICONERROR);
			return 0;
		}
		string l;

		//	List all the devices that are friendly
		string first_line;
		string second_line;
		BOOL FIRSTL = TRUE;
		while (getline(infile, l))
		{
			if (FIRSTL == TRUE)
			{
				first_line = l;
				FIRSTL = FALSE;
			}
			else
			{
				second_line = l;
				FIRSTL = TRUE;
				string MAC_ADDR = first_line.substr(0, 17);
				string IP_ADDR = first_line.substr(20);
				string NAME = second_line;
				PingOneHost(MAC_ADDR, IP_ADDR, NAME);
			}
		}
	
		infile.close();
	}
	return 0;
}
void *NetworkCTRL::ScanSubrangeDevices()
{
	PHOSTENT IP_ADDRESSES;
	int IpAdresses_Count = 0;
	char *ip;
	char hostname[255];
	if (gethostname(hostname, 255) == NULL)
	{
		//MessageBoxA(NULL, hostname, "Hostname:", MB_OK);
		if ((IP_ADDRESSES = gethostbyname(hostname)) != NULL)
		{
			int nCount = 0;
			while (IP_ADDRESSES->h_addr_list[nCount])
			{
				ip = inet_ntoa(*(struct in_addr *)IP_ADDRESSES->h_addr_list[nCount]);
				//MessageBoxA(NULL, ip, "IP: ", MB_OK);
				IpAdresses_Count++;
				nCount++;
			}
		}
		else
		{
			MessageBoxA(NULL, "gethostbyname() failed!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	else
	{
		MessageBoxA(NULL, "gethostname() failed!", "IPS: Error", MB_OK | MB_ICONERROR);
	}
	Sleep(3000);
	for (int i = 0; i < IpAdresses_Count; i++)
	{
		string target = inet_ntoa(*(struct in_addr *)IP_ADDRESSES->h_addr_list[i]);
		SubRangeScanInfo *params = new SubRangeScanInfo();
		params->IpAddr = target;
		params->LuckyNumber = 22;
		if (!CreateThread(NULL, 0, &ScanOneSubrangeDevice, (LPVOID)params, NULL, NULL))
		{
			MessageBoxA(NULL, "Failed to CreateThread()", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}

	return 0;
}
DWORD WINAPI NetworkCTRL::ScanOneSubrangeDevice(LPVOID param)
{
	string target = ((SubRangeScanInfo*)param)->IpAddr;
	string own_ip = target;
	string first_blocks = own_ip.substr(0, own_ip.find_last_of(".") +1);
	//	Convert class name to wstring/TCHAR*
	wstring_convert<std::codecvt<wchar_t, char, std::mbstate_t>> conv;
	wstring wStrMsg = conv.from_bytes(target);

	Notification not((wchar_t*)wStrMsg.c_str());

	// LOOP FOREVER
	while (true)
	{
		//	Scan all subrange 254 ip addresses...
		for (int i = 1; i < 255; i++)
		{
			BOOL TIMED_OUT = FALSE;
			stringstream ss;
			ss << first_blocks << i;
			string IP_ADDR = ss.str();
			string MAC_ADDR = "UNKNOWN_MAC_ADDRS";
			//	CHECK IF THE TARGET IS ONLINE....
			unsigned long IP = INADDR_NONE;
			DWORD dwRetVal = 0;
			char SendData[32] = "abcdefghijklmnopqrstuvwxyz";
			void* ReplyBuffer = NULL;
			DWORD ReplySize = 0;
			//	PINGING IP AND RETRIEVE MAC_ADDR
			HANDLE IcmpFile = IcmpCreateFile();
			if (IcmpFile != INVALID_HANDLE_VALUE)
			{
				IP = stoul(IP_ADDR.c_str(), nullptr, 0);
				ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
				ReplyBuffer = malloc(ReplySize);
				if (ReplyBuffer != NULL)
				{
					IPAddr s = inet_addr(IP_ADDR.c_str());
					dwRetVal = IcmpSendEcho(IcmpFile, s, SendData, sizeof(SendData),
						NULL, ReplyBuffer, ReplySize, 5);
					//	Scan success
					if (dwRetVal != NULL)
					{
						ULONG MacAddr[2];
						ULONG PhysAddrlen = 6;
						BYTE *bPhysAddr;
						memset(&MacAddr, 0xff, sizeof(MacAddr));
						IPAddr SrcIp = 0;
						dwRetVal = SendARP(s, SrcIp, &MacAddr, &PhysAddrlen);
						if (dwRetVal == NO_ERROR)
						{
							bPhysAddr = (BYTE *)&MacAddr;
							if (PhysAddrlen)
							{
								MAC_ADDR = "";
								for (int i = 0; i < (int)PhysAddrlen; i++)
								{
									if (i == (PhysAddrlen - 1))
									{
										stringstream ss;
										ss << std::hex << (int)bPhysAddr[i];
										string part = ss.str();
										if (part.length() == 1)
										{
											part = "0" + part;
										}
										MAC_ADDR = MAC_ADDR + part;
									}
									else
									{
										stringstream ss;
										ss << std::hex << (int)bPhysAddr[i] << ":";
										string part = ss.str();
										if (part.length() == 2)
										{
											part = "0" + part;
										}
										MAC_ADDR = MAC_ADDR + part;
									}
								}
								transform(MAC_ADDR.begin(), MAC_ADDR.end(), MAC_ADDR.begin(), ::toupper);
							}
						}
					}
					//	Scan timed-out.

					else if (WSAGetLastError() == IP_STATUS_BASE + IP_REQ_TIMED_OUT || WSAGetLastError() == 11010)
					{
						TIMED_OUT = TRUE;
					}
					else if (dwRetVal == IP_STATUS_BASE + IP_REQ_TIMED_OUT || dwRetVal == 11010)
					{
						TIMED_OUT = TRUE;
					}
				}
				else
				{
					MessageBoxA(NULL, "Failed to allocate memory!", "IPS: Error", MB_OK | MB_ICONERROR);
				}

			}
			else
			{
				MessageBoxA(NULL, "Failed to create ICMP File!", "IPS: Error", MB_OK | MB_ICONERROR);
			}

			if (TIMED_OUT == TRUE)
			{
				//	Check if it was in our listbox, 
				//	if so delete the item by removing from the file

				//	WORDT M NIET DUS
				/*			
				ifstream ii("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::beg);
				ofstream oo("C:\\Program Files\\IPS\\NetworkData\\Online-Devices2.ips", ios::beg);
				if (!ii)
				{
					MessageBoxA(NULL, "Failed to open Online-Devices.ips file! TIMED_OUT_FUNC", "IPS: Error", MB_OK | MB_ICONERROR);
				}
				else if (!oo)
				{
					MessageBoxA(NULL, "Failed to open Online-Devices2.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
				}
				else
				{
					string line;
					BOOL OFFLINE = FALSE;
					while (getline(ii, line))
					{
						int END = line.find_last_of(" - ");
						string SIN = line.substr(20, END);
						int ENDSIN = SIN.find(" - ");
						string IP = SIN.substr(0, ENDSIN);

						if (IP != IP_ADDR)
						{
							oo << line << endl;
						}
						else
						{
							OFFLINE = TRUE;
						}
					}
					ii.close();
					oo.close();
					String^ SOURCE = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Online-Devices2.ips");
					String^ DEST = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips");
					File::Copy(SOURCE, DEST, TRUE);
					File::Delete(SOURCE);
				}
				*/
				continue;
			}
			BOOL UNKNOWN_FILE = FALSE;
			//	CHECK IF THE TARGET IS ALREADY IN THE UNKNOWN DEVICES FILE
			ifstream iff("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices.ips", ios::beg);
			if (!iff)
			{
				MessageBoxA(NULL, "Failed to open Unknown-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
			}
			else
			{
				string liner;
				while (getline(iff, liner))
				{
					if (liner.find(MAC_ADDR) != string::npos || liner.find(IP_ADDR) != string::npos)
					{
						iff.close();
						UNKNOWN_FILE = TRUE;
						break;
					}
				}
			}

			if (UNKNOWN_FILE == TRUE)
				continue;
			//	IF TARGET IS ONLINE -> CHECK IF IT IS A FRIENDLY DEVICE

			//	USING THE "Online-Devices.ips" FILE....
			ifstream ifs("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::beg);
			//	USING THE "Friendly-Devices.ips" FILE....
			ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Friendly-Devices.ips", ios::beg);
			if (!ifs)
			{
				MessageBoxA(NULL, "Failed to open Online-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
			}
			else if (!infile)
			{
				MessageBoxA(NULL, "Failed to open Friendly-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);

			}

			string line;
			//	CHECKING IN THE "Online-Devices.ips" FILE
			while (getline(ifs, line))
			{
				//	IF IT IS FOUND, BREAK 
				if (line.find(IP_ADDR) != string::npos && line.find(MAC_ADDR) != string::npos)
				{
					ifs.close();
					infile.close();
					break;
				}
				//	CHECK IF IT IS A FRIENDLY DEVICE WITH A OTHER IP
				else
				{
					BOOL SIMILAR_MAC = FALSE;
					string line2;
					//	CHECK IF THE IT IS A FRIENDLY DEVICE WITH A OTHER IP
					while (getline(infile, line2))
					{
						//	If the MAC addr is similar, it is a friendly device.
						if (line2.find(MAC_ADDR) != string::npos)
						{
							string second_line;
							getline(infile, second_line);
							//	Check if the item already exists in the listbox
							
							ifs.close();
							infile.close();
							SIMILAR_MAC = TRUE;
							
							ifstream OnF("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::beg);
							if (!OnF)
							{
								MessageBoxA(NULL, "Failed to open Online-Devices file!", "IPS: Error", MB_OK | MB_ICONERROR);
							}
							else
							{
								string st;
								BOOL EXI = FALSE;
								while (getline(OnF, st))
								{
									if (st.find(MAC_ADDR) != string::npos)
									{
										EXI = TRUE;
										OnF.close();
										break;
									}
								}
								if (EXI == TRUE)
									break;
							}

							//	IF NOT EXISTS
							ofstream of("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::app);
							of << MAC_ADDR << " - " << IP_ADDR << " - " << second_line << endl;
							of.close();

							AliveInfo *info = new AliveInfo();
							info->IP_ADDR = IP_ADDR;
							info->MAC_ADDR = MAC_ADDR;
							CreateThread(NULL, 0, &AliveDevicesLoop, (LPVOID)info, NULL, NULL);
							break;
						}
						else
						{
							//	Skip second line.

							getline(infile, line2);
							continue;
						}
					}
					if (SIMILAR_MAC == TRUE)
						break;
					//	ELSE SAY IF IT IS A UNKNOWN DEVICE.

					//	Get hostname of our unknown device
					string HOSTNAME = "UNKNOWN_HOSTNAME";
					struct hostent*remoteHost;
					struct in_addr addr = { 0 };

					addr.s_addr = inet_addr(IP_ADDR.c_str());
					remoteHost = gethostbyaddr((char *)&addr, 4, AF_INET);

					if (remoteHost != NULL)
					{
						HOSTNAME = remoteHost->h_name;
						if (HOSTNAME == IP_ADDR)
							HOSTNAME = "UNKNOWN_HOSTNAME";
					}

					//	Log it in our Unknown-Devices.ips file
					ofstream off("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices.ips", ios::app);
					off << MAC_ADDR << " - " << IP_ADDR << " - " << HOSTNAME << endl;
					off.close();
					//	Warn user!
					string msg = "Unknown device found!! \n" + IP_ADDR + " + " + MAC_ADDR + " + " + HOSTNAME;
					not.StartNotification(msg);

					ifs.close();
					infile.close();
					break;
				}
			}
		}
		Sleep(2000);
	}
	
}
DWORD WINAPI NetworkCTRL::AliveDevicesLoop(LPVOID param)
{
	AliveInfo* info = (AliveInfo*)param;
	string IP = info->IP_ADDR;
	string MAC = info->MAC_ADDR;

	IPAddr IP_ADDR = inet_addr(IP.c_str());
	if (IP_ADDR == INADDR_NONE)
		return NULL;

	int CountDeaths = 0;

	while (true)
	{
		HANDLE hIcmpFile;
		DWORD retVal = 0;
		char SendData[] = "abcdefghijklmnopqrstuvwxyz";
		LPVOID ReplyBuffer = NULL;
		DWORD ReplySize = 0;

		hIcmpFile = IcmpCreateFile();
		ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
		ReplyBuffer = (VOID*)malloc(ReplySize);

		retVal = IcmpSendEcho(hIcmpFile, IP_ADDR, SendData, sizeof(SendData), NULL, ReplyBuffer, ReplySize, 3000);
		if (retVal == NULL)
		{
			//	Device is dead
			if (CountDeaths == 3)
			{
				ifstream ii("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::beg);
				ofstream oo("C:\\Program Files\\IPS\\NetworkData\\Online-Devices2.ips", ios::beg);

				string line;
				BOOL OFFLINE = FALSE;
				while (getline(ii, line))
				{
					int END = line.find_last_of(" - ");
					string SIN = line.substr(20, END);
					int ENDSIN = SIN.find(" - ");
					string IP_FILE = SIN.substr(0, ENDSIN);

					if (IP_FILE != IP)
					{
						oo << line << endl;
					}
					else
					{
						OFFLINE = TRUE;
					}
				}
				ii.close();
				oo.close();
				String^ SOURCE = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Online-Devices2.ips");
				String^ DEST = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips");
				File::Copy(SOURCE, DEST, TRUE);
				File::Delete(SOURCE);

				return NULL;
			}
			else
				CountDeaths++;
		}
		else
		{
			//	Device is alive
			CountDeaths = 0;
		}
		Sleep(3000);
	}
	return NULL;
}

#endif // !NetworkCTRL_H


//	Scedule startup program
/*
	* Check devices in friendly-devices file, if they are online.
	* Get IP-Adresses of local machine and scan the subrange of that ip
	* Keep scanning until you find a device, and start over.
*/
//	Example of a "Friendly-Devices.ips" file
/*
	All friendly devices:

		192.168.2.xxx - "Friendly Name" + $_Hostname
		192.168.2.xxx - "Friendly Name2" + $_Hostname
	
	All unknown devices:
		192.168.2.xxx - $_Hostname
		192.168.2.xxx - $_Hostname
		
*/