#pragma once
#include "stdafx.h"

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

#ifndef NETSTAT_H
#define NETSTAT_H

class NetStat
{
public:
	NetStat();
	void GET_NETWORKSTATICS_LISTENING(HWND hwndListbox);
	void GET_NETWORKSTATICS_ESTABLISHED(HWND hwndListbox);
	string GET_PROCESSID(DWORD pid);

	int entries_listening = 0;
	int entries_established = 0;
	string process_listening[1000];
	string process_established[1000];

private:
	PMIB_TCPTABLE2 pTcpTable;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;
	char szLocalAddr[128];
	char szRemoteAddr[128];
	struct in_addr IpAddr;
};
NetStat::NetStat()
{
	//	No initializer code required
}
void NetStat::GET_NETWORKSTATICS_LISTENING(HWND HwndListbox)
{
	entries_listening = 0;

	pTcpTable = (MIB_TCPTABLE2 *)MALLOC(sizeof(MIB_TCPTABLE2));
	if (pTcpTable == NULL)
	{
		MessageBoxA(NULL, "Failed allocating memory!", "IPS: Error", MB_OK | MB_ICONERROR);
		return;
	}
	dwSize = sizeof(MIB_TCPTABLE2);
	// Make an initial call to GetTcpTable to
	// get the necessary size into the dwSize variable.
	if ((dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER)
	{
		FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE2 *)MALLOC(dwSize);
		if (pTcpTable == NULL)
		{
			MessageBoxA(NULL, "Error allocating memory!", "IPS: Error", MB_OK | MB_ICONERROR);
			return;
		}
	}
	// Make a second call to GetTcpTable to get
	// the actual data we require.
	if ((dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE)) == NO_ERROR)
	{
		for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++)
		{
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
			strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
			strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));

			if (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN)
			{
				int LocPort = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
				string ITEM;
				stringstream ss;
				ss << szLocalAddr << ":" << LocPort;
				ITEM = ss.str();
				//	Add to the listbox
				SendMessageA(HwndListbox, LB_ADDSTRING, 0, (LPARAM)ITEM.c_str());
				//	Get pid of connection
				string pid = GET_PROCESSID(pTcpTable->table[i].dwOwningPid);
				process_listening[entries_listening] = pid;
				entries_listening++;
			}
			//	Other state, so skipping
		}
	}
	else
	{
		MessageBoxA(NULL, "Failed to get the actual data of the TCP table!", "IPS: Error", MB_OK | MB_ICONERROR);
	}
}
void NetStat::GET_NETWORKSTATICS_ESTABLISHED(HWND HwndListbox)
{
	entries_established = 0;

	pTcpTable = (MIB_TCPTABLE2 *)MALLOC(sizeof(MIB_TCPTABLE2));
	if (pTcpTable == NULL)
	{
		MessageBoxA(NULL, "Failed allocating memory!", "IPS: Error", MB_OK | MB_ICONERROR);
		return;
	}
	dwSize = sizeof(MIB_TCPTABLE2);
	// Make an initial call to GetTcpTable to
	// get the necessary size into the dwSize variable.
	if ((dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER)
	{
		FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE2 *)MALLOC(dwSize);
		if (pTcpTable == NULL)
		{
			MessageBoxA(NULL, "Error allocating memory!", "IPS: Error", MB_OK | MB_ICONERROR);
			return;
		}
	}
	// Make a second call to GetTcpTable to get
	// the actual data we require.
	if ((dwRetVal = GetTcpTable2(pTcpTable, &dwSize, TRUE)) == NO_ERROR)
	{
		for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++)
		{
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
			strcpy_s(szLocalAddr, sizeof(szLocalAddr), inet_ntoa(IpAddr));
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
			strcpy_s(szRemoteAddr, sizeof(szRemoteAddr), inet_ntoa(IpAddr));

			if (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB)
			{
				int LocPort = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
				int RemotePort = ntohs((u_short)pTcpTable->table[i].dwRemotePort);
				string ITEM;
				stringstream ss;
				ss << szLocalAddr << ":" << LocPort 
					<< "  " << szRemoteAddr << ":" << RemotePort;
				ITEM = ss.str();
				//	Add it to the listbox
				SendMessageA(HwndListbox, LB_ADDSTRING, 0, (LPARAM)ITEM.c_str());
				//	Get pid of connection
				string pid = GET_PROCESSID(pTcpTable->table[i].dwOwningPid);
				process_established[entries_established] = pid;
				entries_established++;
			}
			//	Other state, so skipping
		}
	}
	else
	{
		MessageBoxA(NULL, "Failed to get the actual data of the TCP table!", "IPS: Error", MB_OK | MB_ICONERROR);
	}
}
string NetStat::GET_PROCESSID(DWORD pid)
{
	char procId[10];
	sprintf(procId, "%d", pid);
	return procId;
}
#endif // !NETSTAT_H
