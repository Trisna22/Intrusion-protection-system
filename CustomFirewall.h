#pragma once
#include "stdafx.h"

#define BYTE_IPADDR_ARRLEN		4
#define STR_IPADDR_LEN			32
#define VISTA_SUBNET_MASK		0xffffffff


#ifndef CustomFirewall_H
#define CustomFirewall_H

class CustomFirewall
{
public:	// Public constructors
	CustomFirewall();
	~CustomFirewall();
private: // Private variables
	// Structure to store IP address filter.
	typedef struct _IPFILTERINFO {
		BYTE bIpAddrToBlock[BYTE_IPADDR_ARRLEN];
		ULONG uHexAddrToBlock;
		UINT64 u64VistaFilterId;
	} IPFILTERINFO, *PIPFILTERINFO;
	// List of filters.
	typedef std::list<IPFILTERINFO> IPFILTERINFOLIST;

	HANDLE m_hEngineHandle;
	GUID m_subLayerGUID;
	IPFILTERINFOLIST m_lstFilters;
	BOOL FirewallIsRunning = FALSE;
	BOOL ListAdded = FALSE;
public:	// Public functions
	BOOL StartFirewall();
	BOOL StopFirewall();
	void AddToBlockList(string);
	BOOL DeleteFromBlockList(string);
	BOOL AddNewToBlockList(string);
	BOOL FWisRunning();
	BOOL IsIPBlocked(string);
	DWORD Add_RemoveFilter(BOOL);
private: // Private functions
	DWORD Create_DeleteInterfaces(BOOL);
	DWORD Bind_UnBindInterface(BOOL);
	BOOL ParseIPAddrString(string, UINT, BYTE*, UINT, ULONG&);
};
#endif // !CustomFirewall

CustomFirewall::CustomFirewall()
{
	//	Initialize member variables
	m_hEngineHandle = NULL;
	ZeroMemory(&m_subLayerGUID, sizeof(GUID));
	//	Open list blocked IPs file.
	ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips", ios::beg);
	if (!infile)
	{
		MessageBoxA(NULL, "Failed to open Blocked-List file!", "IPS: Error", MB_OK | MB_ICONERROR);
	}
	else
	{
		string line;
		while (getline(infile, line))
		{
			AddToBlockList(line);
		}
		ListAdded = TRUE;
	}
	infile.close();
	//	Start firewall.
	if (FALSE == StartFirewall())
		MessageBoxA(NULL, "Firewall failed to start!", "IPS: Error", MB_OK | MB_ICONWARNING);
}
CustomFirewall::~CustomFirewall()
{
	if (FWisRunning() == FALSE)
		return;
	if (FALSE == StopFirewall())
		MessageBoxA(NULL, "Failed to stop firewall!", "IPS: Error", MB_OK | MB_ICONWARNING);
}
BOOL CustomFirewall::StartFirewall()
{
	if (ListAdded == FALSE)
	{
		//	Open list blocked IPs file.
		ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips", ios::beg);
		if (!infile)
		{
			MessageBoxA(NULL, "Failed to open Blocked-List file!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
		else
		{
			string line;
			while (getline(infile, line))
			{
				AddToBlockList(line);
			}
		}
		infile.close();
		ListAdded = TRUE;
	}
	BOOL bStarted = FALSE;
	//	Create packet filter interface.
	if (ERROR_SUCCESS == Create_DeleteInterfaces(TRUE))
	{
		//	Bind to packet filter interfaces.
		if (ERROR_SUCCESS == Bind_UnBindInterface(TRUE))
		{
			Add_RemoveFilter(TRUE);
			bStarted = TRUE;
			FirewallIsRunning = TRUE;
		}
		else
		{
			MessageBoxA(NULL, "Failed to bind packet filter interface!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	else
	{
		MessageBoxA(NULL, "Failed to create packet filter interface!", "IPS: Error", MB_OK | MB_ICONERROR);
	}
	return bStarted;
}
BOOL CustomFirewall::StopFirewall()
{
	BOOL bStopped = FALSE;
	//	Remove all filters.
	Add_RemoveFilter(FALSE);
	m_lstFilters.clear();
	ListAdded = FALSE;

	//	Unbind from packet filter interface.
	if (ERROR_SUCCESS != Bind_UnBindInterface(FALSE))
	{
		MessageBoxA(NULL, "Failed to unbind from packet filter interface!", "IPS: Error", MB_OK | MB_ICONERROR);
	}
	//	Delete packet filter interface.
	if (ERROR_SUCCESS == Create_DeleteInterfaces(FALSE))
	{
		bStopped = TRUE;
	}
	else
	{
		MessageBoxA(NULL, "Failed to delete filter interface!", "IPS: Error", MB_OK | MB_ICONERROR);
	}
	if (bStopped == TRUE)
		FirewallIsRunning = FALSE;
	return bStopped;
}
void CustomFirewall::AddToBlockList(string szIpAddrToBlock)
{
	if (szIpAddrToBlock.empty() == FALSE)
	{
		IPFILTERINFO stIPFilter = { 0 };

		//	Get byte array format and hex format IP address from string format.
		ParseIPAddrString(szIpAddrToBlock, lstrlenA(szIpAddrToBlock.c_str()),
			stIPFilter.bIpAddrToBlock,
			BYTE_IPADDR_ARRLEN,
			stIPFilter.uHexAddrToBlock);

		//	Push the IP address information to list.
		m_lstFilters.push_back(stIPFilter);
	}
	else
	{
		MessageBoxA(NULL, "No IP Address given to block!", "IPS: Warning", MB_OK | MB_ICONWARNING);
	}
}
BOOL CustomFirewall::DeleteFromBlockList(string IpAddrToDelete) 
{
	//	Adjusting the file with correct data.
	ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips", ios::beg);
	ofstream outfile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List2.ips", ios::trunc | ios::beg);
	if (!infile || !outfile)
	{
		MessageBoxA(NULL, "Failed to open Blocked-List.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	BOOL RULE_DELETED = FALSE;
	string line;
	while (getline(infile, line))
	{
		//	If line isn't similar to IP Addr
		if (line.find(IpAddrToDelete) == string::npos)
			outfile << line << endl;
		//	If line is similar to IP Addr
		else
			RULE_DELETED = TRUE;
	}
	infile.close();
	outfile.close();
	
	//	Check if the rule is acutally deleted.
	if (RULE_DELETED == FALSE)
	{
		MessageBoxA(NULL, "Rule not found in list!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	//	Rename the file back to origin.
	System::String^ FileSource = gcnew System::String("C:\\Program Files\\IPS\\NetworkData\\Blocked-List2.ips");
	System::String^ FileDestination = gcnew System::String("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips");
	File::Copy(FileSource, FileDestination, TRUE);
	File::Delete(FileSource);

	//	Restart filter with the modifications.
	Add_RemoveFilter(FALSE);
	m_lstFilters.clear();
	ifstream infile2("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips", ios::beg);
	if (!infile2)
	{
		MessageBoxA(NULL, "Failed to open Blocked-List file!", "IPS: Error", MB_OK | MB_ICONERROR);
	}
	else
	{
		string line;
		while (getline(infile2, line))
		{
			AddToBlockList(line);
		}
	}
	infile2.close();
	Add_RemoveFilter(TRUE);

	return TRUE;
}
BOOL CustomFirewall::AddNewToBlockList(string IpAddrToAdd)
{
	//	Add IP to list in file.
	ofstream outfile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips", ios::app);
	if (!outfile)
	{
		MessageBoxA(NULL, "Failed to open Blocked-List.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
	outfile << IpAddrToAdd << endl;
	outfile.close();
	
	//	Restart filter with the modifications.
	Add_RemoveFilter(FALSE);
	m_lstFilters.clear();
	ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips");
	if (!infile)
	{
		MessageBoxA(NULL, "Failed to open Blocked-List.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
	else
	{
		string line;
		while (getline(infile, line))
		{
			AddToBlockList(line);
		}
	}
	infile.close();
	Add_RemoveFilter(TRUE);

	return TRUE;
}
BOOL CustomFirewall::FWisRunning()
{
	return FirewallIsRunning;
}
BOOL CustomFirewall::IsIPBlocked(string ip)
{
	ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips", ios::beg);
	if (!infile)
	{
		MessageBoxA(NULL, "Failed to open Blocked-List.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
	string line;
	while (getline(infile, line))
	{
		if (line == ip)
		{
			infile.close();
			return TRUE;
		}
	}
	infile.close();
	return FALSE;
}
DWORD CustomFirewall::Create_DeleteInterfaces(BOOL bCreate)
{
	DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
	if (bCreate == TRUE)
	{
		//	Create packet filter interface.
		dwFwAPiRetCode = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT,
			NULL, NULL, &m_hEngineHandle);
	}
	else
	{
		if (NULL != m_hEngineHandle)
		{
			//	Close packet filter interface
			dwFwAPiRetCode = FwpmEngineClose0(m_hEngineHandle);
			m_hEngineHandle = NULL;
		}
	}
	return dwFwAPiRetCode;
}
DWORD CustomFirewall::Bind_UnBindInterface(BOOL bBind)
{
	DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
	if (bBind == TRUE)
	{
		RPC_STATUS rpcStatus = { 0 };
		FWPM_SUBLAYER0 SubLayer = { 0 };

		//	Create a GUID for our packet filter layer.
		rpcStatus = UuidCreate(&SubLayer.subLayerKey);
		if (NO_ERROR == rpcStatus)
		{
			//	Save GUID
			CopyMemory(&m_subLayerGUID,
				&SubLayer.subLayerKey,
				sizeof(SubLayer.subLayerKey));
			//	Populate packet filter layer information
			SubLayer.displayData.name = L"CustomFirewall";
			SubLayer.displayData.description = L"CustomFirewall of IPS";
			SubLayer.flags = 0;
			SubLayer.weight = 0x100;

			// Add packet filter to our interface.
			dwFwAPiRetCode = ::FwpmSubLayerAdd0(m_hEngineHandle,
				&SubLayer,
				NULL);
		}
	}
	else
	{
		//	Delete packet filter layer from interface.
		dwFwAPiRetCode = FwpmSubLayerDeleteByKey0(m_hEngineHandle, &m_subLayerGUID);
		ZeroMemory(&m_subLayerGUID, sizeof(GUID));
	}
	return dwFwAPiRetCode;
}
DWORD CustomFirewall::Add_RemoveFilter(BOOL bAdd)
{
	DWORD dwFwAPiRetCode = ERROR_BAD_COMMAND;
	if (bAdd == TRUE)
	{
		//	Add filter
		if (m_lstFilters.size())
		{
			IPFILTERINFOLIST::iterator itFilter;
			for (itFilter = m_lstFilters.begin(); itFilter != m_lstFilters.end(); itFilter++)
			{
				if ((NULL != itFilter->bIpAddrToBlock) && (0 != itFilter->uHexAddrToBlock))
				{
					FWPM_FILTER0 Filter = { 0 };
					FWPM_FILTER_CONDITION0 Condition = { 0 };
					FWP_V4_ADDR_AND_MASK AddrMask = { 0 };

					//	Prepare filter condition
					Filter.subLayerKey = m_subLayerGUID;
					Filter.displayData.name = L"CustomFirewall";
					Filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
					Filter.action.type = FWP_ACTION_BLOCK;
					Filter.weight.type = FWP_EMPTY;
					Filter.filterCondition = &Condition;
					Filter.numFilterConditions = 1;

					// Remote IP address should match itFilters->uHexAddrToBlock.
					Condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
					Condition.matchType = FWP_MATCH_EQUAL;
					Condition.conditionValue.type = FWP_V4_ADDR_MASK;
					Condition.conditionValue.v4AddrMask = &AddrMask;

					//	Add IP address to be blocked
					AddrMask.addr = itFilter->uHexAddrToBlock;
					AddrMask.mask = VISTA_SUBNET_MASK;

					// Add filter condition to our interface. Save filter id in itFilters->u64VistaFilterId.
					dwFwAPiRetCode = ::FwpmFilterAdd0(m_hEngineHandle,
						&Filter,
						NULL,
						&(itFilter->u64VistaFilterId));
				}
			}
		}
	}
	else
	{
		//	Remove filter
		if (m_lstFilters.size())
		{
			IPFILTERINFOLIST::iterator itFilter;
			for (itFilter = m_lstFilters.begin(); itFilter != m_lstFilters.end(); itFilter++)
			{
				if ((NULL != itFilter->bIpAddrToBlock) && (NULL != itFilter->uHexAddrToBlock))
				{
					//	Delete all previously added filters.
					dwFwAPiRetCode = FwpmFilterDeleteById0(m_hEngineHandle, itFilter->u64VistaFilterId);
					itFilter->u64VistaFilterId = NULL;
				}
			}
		}
	}
	return dwFwAPiRetCode;
}
BOOL CustomFirewall::ParseIPAddrString(string szIpAddr, UINT nStrLen, BYTE* pbHostOrder, UINT nByteLen, ULONG &uHexAddr)
{
	BOOL bRet = TRUE;
	UINT i = 0;
	UINT j = 0;
	UINT nPack = 0;
	char szTemp[2];

	//	Build byte array format from string format
	for (; (i < nStrLen) && (j < nByteLen);)
	{
		if ('.' != szIpAddr[i])
		{
			StringCchPrintfA(szTemp, 2, "%c", szIpAddr[i]);
			nPack = (nPack * 10) + atoi(szTemp);
		}
		else
		{
			pbHostOrder[j] = nPack;
			nPack = 0;
			j++;
		}
		i++;
	}
	if (j < nByteLen)
	{
		pbHostOrder[j] = nPack;

		// Build hex format from byte array format.
		for (j = 0; j < nByteLen; j++)
		{
			uHexAddr = (uHexAddr << 8) + pbHostOrder[j];
		}

	}
	return bRet;
}
