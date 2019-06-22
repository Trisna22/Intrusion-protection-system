#pragma once
/*
	Project Information:____

	* Name:			Intrusion Protection System (IPS)
	* Author:		Trisna Quebe
	* Language:		c++ win32
	* CopyRights:	23-11-2017
	* Description:	Protects a computer/network against 
					virusses and hack attacks.

*/
#include <iostream>
#include <string>
#include <Windows.h>
#include <windowsx.h>
#include <WinUser.h>
#include <CommCtrl.h>
#include <IPHlpApi.h>
#include <sstream>
#include <Psapi.h>
#include <netfw.h>
#include <winternl.h>
#include <fstream>
#include <IcmpAPI.h>
#include <algorithm>
#include <locale>
#include <codecvt>
#include <fwpmu.h>
#include <list>
#include <strsafe.h>

using namespace std;
using namespace System;
using namespace System::Threading;

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,  "Shell32.lib")
#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")


#ifndef UNICODE
#define UNICODE
#endif // !UNICODE
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // !WIN32_LEAN_AND_MEAN

