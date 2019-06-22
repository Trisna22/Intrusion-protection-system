#include "stdafx.h"
#include "Resource.h"

#include "SoftwareInstall.h"
#include "NetStatics.h"
#include "NetworkCTRL.h"
#include "CustomFirewall.h"

namespace MainWindow
{
	//	MainWindow Functions
	BOOL RegisterOurClass(HINSTANCE hInstance);
	BOOL CreateOurWindow(HINSTANCE hInstance, int nCmdShow);
	void InitializeComponents(HWND HwndMain);
	void SetIcon(HWND Hwndmain);
	
	LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
	
	HWND HwndParent;
	HWND HwndDialog;

	CustomFirewall firewall;
}
namespace NetstatDialog
{
	//	Dialog Functions
	BOOL RegisterDialog(HINSTANCE);
	BOOL StartDialog(HINSTANCE, HWND);
	void InitializeDialog(HWND);
	void SetIcon(HWND);

	void UpdateProcessID(HWND, string);
	void UpdateConnInfoLabel(HWND, TCHAR*);
	BOOL KillProcess(DWORD);

	LRESULT CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);

	HWND HwndParent;
	HWND HwndDialog;
	BOOL DialogShown = FALSE;
	HANDLE DialogHandle;
	DWORD dwThreadID;

	NetStat netstat;

	//	Global Functions
	void *ShowDialog(HWND, HINSTANCE);
	void CloseDialog();
	BOOL LoadAndBlitBitMap(LPCWSTR, HDC);

}
namespace WindowsFirewallDialog
{
	//	Dialog Functions
	BOOL RegisterDialog(HINSTANCE);
	BOOL StartDialog(HINSTANCE, HWND);
	void InitializeDialog(HWND);
	void SetIcon(HWND);

	BOOL DialogShown = FALSE;
	HANDLE DialogHandle;
	DWORD dwThreadID;

	LRESULT CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);
	
	//	Global Functions
	void *ShowDialog(HWND, HINSTANCE);
	void CloseDialog();
	BOOL GetFirewallInformation(HWND);
	HRESULT WFCOMInitialize(INetFwPolicy2**);
	void SetLabelText(int, HWND, string);
	BOOL LoadAndBlitBitMap(LPCWSTR, HDC);
}
namespace NetworkCTRLDialog
{
	//	Dialog Functions
	BOOL RegisterDialog(HINSTANCE);
	BOOL StartDialog(HINSTANCE, HWND);
	void InitializeDialog(HWND);
	void SetIcon(HWND);

	BOOL DialogShown = FALSE;
	HANDLE DialogHandle;
	DWORD dwThreadID;
	HWND HwndMain;
	
	NetworkCTRL netCTRL;

	LRESULT CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);
	
	//	Global Functions
	void *ShowDialog(HWND, HINSTANCE);
	void CloseDialog();
	void *LoopingOnlineDevices(HWND);
	void *LoopingUnknownDevices(HWND);
	void LoopFileIndex(HWND);
	void AddToFriendlyDevices(string, string, string);
	void SetSTATICText(int, string, HWND);
	void RemoveFromList(string);

	//	Global Variables
	HANDLE OnlineDevThread;
	DWORD dwOnlineDevThreadID;
	HANDLE UnknownDevThread;
	DWORD dwUnknownDevThread;
}
namespace CustomFirewallDialog
{
	//	CustomFirewallDialog
	BOOL RegisterDialog(HINSTANCE);
	BOOL StartDialog(HINSTANCE, HWND);
	void InitializeDialog(HWND);
	void SetIcon(HWND);

	BOOL DialogShown = FALSE;
	HANDLE DialogHandle;
	DWORD dwThreadID;
	HWND HwndDialog;

	LRESULT CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);

	//	Global Variables
	void *ShowDialog(HWND, HINSTANCE);
	void CloseDialog();
	void SetSTATICText(int, string, HWND);
}
namespace ActionWindow
{
	BOOL RegisterActionWindow(HINSTANCE);
	BOOL StartActionWindow(HINSTANCE, HWND);
	void InitializeActionWindow(HINSTANCE, HWND, string);
	void SetIcon(HWND);

	HWND ActionWindowHwnd;
	BOOL WindowOpen = FALSE;

	LRESULT CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);

	//	Global Functions
	void *ShowActionWindow(HWND, HINSTANCE, string);
	void CleanupActionWindow();

	BOOL RegisterActionWindow(HINSTANCE hInstance)
	{
		WNDCLASSEX wc;
		wc.cbSize = sizeof(WNDCLASSEX);
		wc.style = NULL;
		wc.lpfnWndProc = ActionWindow::DialogProc;
		wc.cbClsExtra = 0;
		wc.cbWndExtra = 0;
		wc.hInstance = hInstance;
		wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
		wc.hCursor = LoadIcon(NULL, IDC_HAND);
		wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
		wc.lpszMenuName = L"TITLE";
		wc.lpszClassName = L"ActionWindow";
		wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
		return RegisterClassEx(&wc);
	}
	BOOL StartActionWindow(HINSTANCE hInstance, HWND HwndParent)
	{
		RECT desktop;
		GetWindowRect(HwndParent, &desktop);
		int XPos = desktop.left + 200;
		int YPos = desktop.top + 150;
		HWND hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, L"ActionWindow", L"Actions to peform:", WS_SYSMENU | WS_CAPTION | SWP_NOSIZE | SWP_NOMOVE, XPos, YPos, 400, 400, HwndParent, NULL, hInstance, NULL);
		if (hwnd == NULL)
		{
			MessageBoxA(HwndParent, "Failed to create a ActionWindow!", "IPS: Error", MB_OK | MB_ICONERROR);
			return FALSE;
		}
		ActionWindowHwnd = hwnd;
		ShowWindow(hwnd, SW_SHOW);
		UpdateWindow(hwnd);
		return TRUE;
	}
	void InitializeActionWindow(HINSTANCE hInstance, HWND HwndParent, string DeviceData)
	{
		//	TODO: Add Constructor code
		int END = DeviceData.find_last_of(" - ");
		string SIN = DeviceData.substr(20, END);
		int ENDSIN = SIN.find(" - ");
		string IP_ADDR = SIN.substr(0, ENDSIN);
		string MAC_ADDR = DeviceData.substr(0, 17);
		string HOSTNAME = SIN.substr(ENDSIN + 3);

		HWND InfoDev = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"Information Device:",
			WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
			10, 10, 150, 20,
			HwndParent, NULL,
			hInstance, NULL);

		HWND LABELHOSTNAME = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", "Hostname: ", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			20, 40, 400, 20,
			HwndParent, (HMENU)"HOSTNAME",
			hInstance, NULL);

		HWND LABELHOSTNAME2 = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", HOSTNAME.c_str(), WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			180, 40, 400, 20,
			HwndParent, (HMENU)LABEL_HOSTNAME,
			hInstance, NULL);

		HWND LABELMAC = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", "MAC Address:", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			20, 60, 400, 20,
			HwndParent, (HMENU)"MAC_ADDR",
			hInstance, NULL);

		HWND LABELMAC2 = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", MAC_ADDR.c_str(), WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			180, 60, 400, 20,
			HwndParent, (HMENU)LABEL_MACADDR,
			hInstance, NULL);

		HWND LABELIP = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", "IP Address: ", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			20, 80, 400, 20,
			HwndParent, (HMENU)"IP_ADDR",
			hInstance, NULL);

		HWND LABELIP2 = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", IP_ADDR.c_str(), WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			180, 80, 400, 20,
			HwndParent, (HMENU)LABEL_IPADDR,
			hInstance, NULL);

		HWND LABELWFPSTATUS = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"WFP Status:", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			20, 100, 100, 20,
			HwndParent, NULL,
			hInstance, NULL);

		HWND BtnDeleteFromListBox = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON", L"Delete from listbox",
			WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
			10, 140, 200, 30,
			HwndParent, (HMENU)BTN_REMOVELISTBOX,
			hInstance, NULL);

		//	LABEL WFP STATUS
		if (MainWindow::firewall.IsIPBlocked(IP_ADDR) == TRUE)
		{
			HWND Status = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"Blocked", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
				180, 100, 100, 20,
				HwndParent, NULL,
				hInstance, NULL);
			HWND BtnBlockIP = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON", L"Allow IP Address", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
				10, 180, 200, 30,
				HwndParent, (HMENU)BTN_BLOCKIP,
				hInstance, NULL);
		}
		else
		{
			HWND Status = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"Allow", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
				180, 100, 100, 20,
				HwndParent, NULL,
				hInstance, NULL);
			HWND BtnBlockIP = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON", L"Block IP Address", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
				10, 180, 200, 30,
				HwndParent, (HMENU)BTN_BLOCKIP,
				hInstance, NULL);
		}

		HWND BtnAddFriendlyList = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON", L"Add to friendly devices",
			WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
			10, 220, 200, 30,
			HwndParent, (HMENU)BTN_ADDFRIENDLYLIST,
			hInstance, NULL);
	}
	void SetIcon(HWND hwnd)
	{
		HICON IconSmall = NULL;
		HICON IconBig = NULL;

		if ((IconSmall = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
		{
			if ((IconSmall = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
			{
				MessageBoxA(NULL, "Failed to load small icon!", "IPS: Error", MB_OK | MB_ICONERROR);
			}
		}
		if ((IconBig = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
		{
			if ((IconBig = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
			{
				MessageBoxA(NULL, "Failed to load big icon!", "IPS: Error", MB_OK | MB_ICONERROR);
			}
		}
		SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)IconSmall);
		SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)IconBig);
		return;
	}
	void* ShowActionWindow(HWND hwnd, HINSTANCE hInstance, string device)
	{
		if (!RegisterActionWindow(hInstance))
		{
			MessageBoxA(NULL, "Failed to Register ActionWindow Class!", "IPS: Error", MB_OK | MB_ICONERROR);
			return 0;
		}
		if (!StartActionWindow(hInstance, hwnd))
		{
			MessageBoxA(NULL, "Failed to StartActionWindow()!", "IPS: Error", MB_OK | MB_ICONERROR);
			return 0;
		}

		//	Initialize our action window with the data.
		InitializeActionWindow(hInstance, ActionWindowHwnd, device);
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0) > 0)
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		CleanupActionWindow();
	}
	void CleanupActionWindow()
	{
		WindowOpen = FALSE;
		BOOL result = UnregisterClassA("ActionWindow", (HINSTANCE)GetModuleHandle(L"ActionWindow"));
		if (result == FALSE)
		{
			if (GetLastError() == 1411)
				return;
			stringstream ss;
			ss << "UnRegisterClass failed with error: " << GetLastError() << endl;
			MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	LRESULT CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		switch (msg)
		{
		case WM_CREATE:
		{
			SetIcon(hwnd);
			WindowOpen = TRUE;
			break;
		}
		case WM_DESTROY:
		{
			PostQuitMessage(0);
			break;
		}
		case WM_CTLCOLORSTATIC:
		{
			HDC hdcStatic = (HDC)wParam;
			SetTextColor(hdcStatic, RGB(255, 255, 255));
			SetBkMode(hdcStatic, TRANSPARENT);
			return (LRESULT)GetStockObject(NULL_BRUSH);
		}
		case WM_COMMAND:
		{
			switch (LOWORD(wParam))
			{
			case BTN_BLOCKIP:
			{
				switch (HIWORD(wParam))
				{
				case BN_CLICKED:
				{
					HWND hwndDialog;
					if ((hwndDialog = FindWindowExA(NULL, NULL, "CustomFirewallDialog", NULL)) == NULL)
					{
						//	Dialog not opened
						CustomFirewallDialog::DialogHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CustomFirewallDialog::ShowDialog, NULL, NULL, &CustomFirewallDialog::dwThreadID);
						if (!CustomFirewallDialog::DialogHandle)
						{
							MessageBoxA(NULL, "Failed to open CustomFirewall Window!", "IPS: Error", MB_OK | MB_ICONERROR);
							break;
						}

						//	Give the window some delay time
						Sleep(800);

						//	SET IPADDR IN TEXTBOX
						TCHAR buff[MAX_PATH];
						GetWindowText(GetDlgItem(hwnd, LABEL_IPADDR), buff, MAX_PATH);
						wstring str = buff;
						string IP_ADDR = string(str.begin(), str.end());
						hwndDialog = FindWindowExA(NULL, NULL, "CustomFirewallDialog", NULL);
						//	Check if we have to block or allow the IP
						if (MainWindow::firewall.IsIPBlocked(IP_ADDR) == TRUE)
						{
							//	Add to potential allow list.
							NetworkCTRLDialog::SetSTATICText(RULETODELETE_LABEL, IP_ADDR, hwndDialog);
						}
						else
						{
							//	Add to potential block list.
							SetWindowTextA(GetDlgItem(hwndDialog, IPADDR_TEXTBOX), IP_ADDR.c_str());
						}
						PostMessage(hwnd, WM_CLOSE, 0, 0);
					}
					else
					{
						//	Dialog already opened
						SetForegroundWindow(hwndDialog);

						//	Give the window some delay time.
						Sleep(800);

						//	SET IPADDR IN TEXTBOX
						TCHAR buff[MAX_PATH];
						GetWindowText(GetDlgItem(hwnd, LABEL_IPADDR), buff, MAX_PATH);
						wstring str = buff;
						string IP_ADDR = string(str.begin(), str.end());
						hwndDialog = FindWindowExA(NULL, NULL, "CustomFirewallDialog", NULL);
						//	Check if we have to block or allow the IP
						if (MainWindow::firewall.IsIPBlocked(IP_ADDR) == TRUE)
						{
							//	Add to potential allow list.
							NetworkCTRLDialog::SetSTATICText(RULETODELETE_LABEL, IP_ADDR, hwndDialog);
						}
						else
						{
							//	Add to potential block list.
							SetWindowTextA(GetDlgItem(hwndDialog, IPADDR_TEXTBOX), IP_ADDR.c_str());
						}
						PostMessage(hwnd, WM_CLOSE, 0, 0);
					}
					break;
				}
				default:
					break;
				}
				break;
			}
			case BTN_REMOVELISTBOX:
			{
				switch (HIWORD(wParam))
				{
				case BN_CLICKED:
				{
					int ID = MessageBoxA(hwnd, "Are you sure to delete this IP from listbox?", "IPS: Info", MB_YESNO | MB_ICONQUESTION);
					switch (ID)
					{
					case IDNO:
						return DefWindowProc(hwnd, msg, wParam, lParam);
					default:
						break;
					}

					TCHAR buff[MAX_PATH];
					GetWindowText(GetDlgItem(hwnd, LABEL_IPADDR), buff, MAX_PATH);
					wstring str = buff;
					string IP = string(str.begin(), str.end());

					ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices.ips", ios::beg);
					ofstream outfile("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices2.ips", ios::beg);
					if (!infile)
					{
						MessageBoxA(hwnd, "Failed to open Unknown-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
						break;
					}
					else if (!outfile)
					{
						MessageBoxA(hwnd, "Failed to open Unknown-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
						break;
					}

					BOOL DELETED = FALSE;
					string line;
					while (getline(infile, line))
					{
						if (line.find(IP) == string::npos)
							outfile << line << endl;
						else
							DELETED = TRUE;
					}
					infile.close();
					outfile.close();
					
					//	Rename file and delete the temp file.
					String^ SOURCE = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices2.ips");
					String^ DEST = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices.ips");
					File::Copy(SOURCE, DEST, TRUE);
					File::Delete(SOURCE);


					if (DELETED == FALSE)
						MessageBoxA(hwnd, "Failed to delete IP from listbox!", "IPS: Error", MB_OK | MB_ICONERROR);
					else
						MessageBoxA(hwnd, "IP succesfully deleted from listbox! \n(Wait a few seconds if not)", "IPS: Info", MB_OK | MB_ICONEXCLAMATION);
					
					PostMessage(hwnd, WM_CLOSE, 0, 0);
					SetForegroundWindow(FindWindowEx(NULL, NULL, L"NetworkCTRLDialog", NULL));
					break;
				}
				default:
					break;
				}
				break;
			}
			case BTN_ADDFRIENDLYLIST:
			{
				switch (HIWORD(wParam))
				{
				case BN_CLICKED:
				{
					//	Get data from device
					TCHAR buff[MAX_PATH];
					GetWindowText(GetDlgItem(hwnd, LABEL_MACADDR), buff, MAX_PATH);
					wstring strMAC = buff;
					GetWindowText(GetDlgItem(hwnd, LABEL_IPADDR), buff, MAX_PATH);
					wstring strIP = buff;
					GetWindowText(GetDlgItem(hwnd, LABEL_HOSTNAME), buff, MAX_PATH);
					wstring strNAME = buff;
					//	Cast wstring to string
					string MAC_ADDR = string(strMAC.begin(), strMAC.end());
					string IP_ADDR = string(strIP.begin(), strIP.end());
					string HOSTNAME = string(strNAME.begin(), strNAME.end());
					//	Put the values in textboxes
					HWND Window = FindWindowEx(NULL, NULL, L"NetworkCTRLDialog", NULL);
					NetworkCTRLDialog::SetSTATICText(EDIT_MACADDR, MAC_ADDR, Window);
					NetworkCTRLDialog::SetSTATICText(EDIT_IPADDR, IP_ADDR, Window);
					PostMessage(hwnd, WM_CLOSE, 0, 0);
					SetForegroundWindow(FindWindowEx(NULL, NULL, L"NetworkCTRLDialog", NULL));
				}
				default:
					break;
				}
				break;
			}
			default:
				break;
			}
			break;
		}
		case WM_CLOSE:
		{
			CloseWindow(hwnd);
			DestroyWindow(hwnd);
			break;
		}
		default:
			return DefWindowProc(hwnd, msg, wParam, lParam);
		}
	}
}
namespace ActionWindow2
{
	BOOL RegisterActionWindow(HINSTANCE);
	BOOL StartActionWindow(HINSTANCE, HWND);
	void InitializeActionWindow(HINSTANCE, HWND, string);
	void SetIcon(HWND);

	HWND ActionWindowHwnd;
	BOOL WindowOpen = FALSE;

	LRESULT CALLBACK DialogProc(HWND, UINT, WPARAM, LPARAM);

	//	Global Functions
	void *ShowActionWindow(HWND, HINSTANCE, string);
	void CleanupActionWindow();

	BOOL RegisterActionWindow(HINSTANCE hInstance)
	{
		WNDCLASSEX wc;
		wc.cbSize = sizeof(WNDCLASSEX);
		wc.style = NULL;
		wc.lpfnWndProc = ActionWindow2::DialogProc;
		wc.cbClsExtra = 0;
		wc.cbWndExtra = 0;
		wc.hInstance = hInstance;
		wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
		wc.hCursor = LoadIcon(NULL, IDC_HAND);
		wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
		wc.lpszMenuName = L"TITLE";
		wc.lpszClassName = L"ActionWindow2";
		wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
		return RegisterClassEx(&wc);
	}
	BOOL StartActionWindow(HINSTANCE hInstance, HWND HwndParent)
	{
		RECT desktop;
		GetWindowRect(HwndParent, &desktop);
		int XPos = desktop.left + 200; 
		int YPos = desktop.top + 150;
		HWND hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, L"ActionWindow2", L"Actions to peform:", WS_SYSMENU | WS_CAPTION | SWP_NOSIZE | SWP_NOMOVE, XPos, YPos, 400, 400, HwndParent, NULL, hInstance, NULL);
		if (hwnd == NULL)
		{
			MessageBoxA(HwndParent, "Failed to create a ActionWindow2!", "IPS: Error", MB_OK | MB_ICONERROR);
			return FALSE;
		}
		ActionWindowHwnd = hwnd;
		ShowWindow(hwnd, SW_SHOW);
		UpdateWindow(hwnd);
		return TRUE;
	}
	void InitializeActionWindow(HINSTANCE hInstance, HWND HwndParent, string DeviceData)
	{
		//	TODO: Add Constructor code
		int END = DeviceData.find_last_of(" - ");
		string SIN = DeviceData.substr(20, END);
		int ENDSIN = SIN.find(" - ");
		string IP_ADDR = SIN.substr(0, ENDSIN);
		string MAC_ADDR = DeviceData.substr(0, 17);
		string HOSTNAME = SIN.substr(ENDSIN + 3);

		HWND InfoDev = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"Information Device:",
			WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
			10, 10, 150, 20,
			HwndParent, NULL,
			hInstance, NULL);

		HWND LABELHOSTNAME = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", "Friendly Name: ", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			20, 40, 400, 20,
			HwndParent, (HMENU)"HOSTNAME",
			hInstance, NULL);

		HWND LABELHOSTNAME2 = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", HOSTNAME.c_str(), WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			180, 40, 400, 20,
			HwndParent, (HMENU)LABEL_HOSTNAME,
			hInstance, NULL);

		HWND LABELMAC = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", "MAC Address:", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			20, 60, 400, 20,
			HwndParent, (HMENU)"MAC_ADDR",
			hInstance, NULL);

		HWND LABELMAC2 = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", MAC_ADDR.c_str(), WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			180, 60, 400, 20,
			HwndParent, (HMENU)LABEL_MACADDR,
			hInstance, NULL);

		HWND LABELIP = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", "IP Address: ", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			20, 80, 400, 20,
			HwndParent, (HMENU)"IP_ADDR",
			hInstance, NULL);

		HWND LABELIP2 = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", IP_ADDR.c_str(), WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			180, 80, 400, 20,
			HwndParent, (HMENU)LABEL_IPADDR,
			hInstance, NULL);

		HWND LABELWFPSTATUS = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"WFP Status:", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
			20, 100, 100, 20,
			HwndParent, NULL,
			hInstance, NULL);

		//	LABEL WFP STATUS
		if (MainWindow::firewall.IsIPBlocked(IP_ADDR) == TRUE)
		{
			HWND Status = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"Blocked", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
				180, 100, 100, 20,
				HwndParent, NULL,
				hInstance, NULL);
			HWND BtnBlockIP = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON", L"Allow IP Address", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
				10, 180, 200, 30,
				HwndParent, (HMENU)BTN_BLOCKIP,
				hInstance, NULL);
		}
		else
		{
			HWND Status = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"Allow", WS_VISIBLE | SS_LEFT | WS_CHILD | WS_SYSMENU,
				180, 100, 100, 20,
				HwndParent, NULL,
				hInstance, NULL);
			HWND BtnBlockIP = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON", L"Block IP Address", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
				10, 180, 200, 30,
				HwndParent, (HMENU)BTN_BLOCKIP,
				hInstance, NULL);
		}

		HWND BtnDeleteFromListBox = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON", L"Delete from listbox",
			WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
			10, 140, 200, 30,
			HwndParent, (HMENU)BTN_REMOVELISTBOX,
			hInstance, NULL);
	}
	void SetIcon(HWND hwnd)
	{
		HICON IconSmall = NULL;
		HICON IconBig = NULL;

		if ((IconSmall = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
		{
			if ((IconSmall = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
			{
				MessageBoxA(NULL, "Failed to load small icon!", "IPS: Error", MB_OK | MB_ICONERROR);
			}
		}
		if ((IconBig = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
		{
			if ((IconBig = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
			{
				MessageBoxA(NULL, "Failed to load big icon!", "IPS: Error", MB_OK | MB_ICONERROR);
			}
		}
		SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)IconSmall);
		SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)IconBig);
		return;
	}
	void* ShowActionWindow(HWND hwnd, HINSTANCE hInstance, string device)
	{
		if (!RegisterActionWindow(hInstance))
		{
			MessageBoxA(NULL, "Failed to Register ActionWindow2 Class!", "IPS: Error", MB_OK | MB_ICONERROR);
			return 0;
		}
		if (!StartActionWindow(hInstance, hwnd))
		{
			MessageBoxA(NULL, "Failed to StartActionWindow2()!", "IPS: Error", MB_OK | MB_ICONERROR);
			return 0;
		}

		//	Initialize our action window with the data.
		InitializeActionWindow(hInstance, ActionWindowHwnd, device);
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0) > 0)
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		CleanupActionWindow();
	}
	void CleanupActionWindow()
	{
		WindowOpen = FALSE;
		BOOL result = UnregisterClassA("ActionWindow2", (HINSTANCE)GetModuleHandle(L"ActionWindow2"));
		if (result == FALSE)
		{
			if (GetLastError() == 1411)
				return;
			stringstream ss;
			ss << "UnRegisterClass failed with error: " << GetLastError() << endl;
			MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	LRESULT CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		switch (msg)
		{
		case WM_CREATE:
		{
			SetIcon(hwnd);
			WindowOpen = TRUE;
			break;
		}
		case WM_CTLCOLORSTATIC:
		{
			HDC hdcStatic = (HDC)wParam;
			SetTextColor(hdcStatic, RGB(255, 255, 255));
			SetBkMode(hdcStatic, TRANSPARENT);
			return (LRESULT)GetStockObject(NULL_BRUSH);
		}
		case WM_COMMAND:
		{
			switch (LOWORD(wParam))
			{
			case BTN_REMOVELISTBOX:
			{
				switch (HIWORD(wParam))
				{
				case BN_CLICKED:
				{
					int ID = MessageBoxA(hwnd, "Are you sure to delete this IP from listbox?", "IPS: Info", MB_YESNO | MB_ICONQUESTION);
					switch (ID)
					{
					case IDNO:
						return DefWindowProc(hwnd, msg, wParam, lParam);
					default:
						break;
					}

					TCHAR buff[MAX_PATH];
					GetWindowText(GetDlgItem(hwnd, LABEL_IPADDR), buff, MAX_PATH);
					wstring str = buff;
					string IP = string(str.begin(), str.end());

					ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::beg);
					ofstream outfile("C:\\Program Files\\IPS\\NetworkData\\Online-Devices2.ips", ios::beg);
					if (!infile)
					{
						MessageBoxA(hwnd, "Failed to open Online-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
						break;
					}
					else if (!outfile)
					{
						MessageBoxA(hwnd, "Failed to open Online-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
						break;
					}

					BOOL DELETED = FALSE;
					string line;
					while (getline(infile, line))
					{
						if (line.find(IP) == string::npos)
							outfile << line << endl;
						else
							DELETED = TRUE;
					}
					infile.close();
					outfile.close();

					//	Rename file and delete the temp file.
					String^ SOURCE = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Online-Devices2.ips");
					String^ DEST = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips");
					File::Copy(SOURCE, DEST, TRUE);
					File::Delete(SOURCE);


					if (DELETED == FALSE)
						MessageBoxA(hwnd, "Failed to delete IP from listbox!", "IPS: Error", MB_OK | MB_ICONERROR);
					else
						MessageBoxA(hwnd, "IP succesfully deleted from listbox! \n(Wait a few seconds if not)", "IPS: Info", MB_OK | MB_ICONEXCLAMATION);

					PostMessage(hwnd, WM_CLOSE, 0, 0);
					SetForegroundWindow(FindWindowEx(NULL, NULL, L"NetworkCTRLDialog", NULL));
					break;
				}
				default:
					break;
				}
				break;
			}
			case BTN_BLOCKIP:
			{
				HWND hwndDialog;
				if ((hwndDialog = FindWindowExA(NULL, NULL, "CustomFirewallDialog", NULL)) == NULL)
				{
					//	Dialog not opened
					CustomFirewallDialog::DialogHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CustomFirewallDialog::ShowDialog, NULL, NULL, &CustomFirewallDialog::dwThreadID);
					if (!CustomFirewallDialog::DialogHandle)
					{
						MessageBoxA(NULL, "Failed to open CustomFirewall Window!", "IPS: Error", MB_OK | MB_ICONERROR);
						break;
					}

					//	Give the window some delay time
					Sleep(800);

					//	SET IPADDR IN TEXTBOX
					TCHAR buff[MAX_PATH];
					GetWindowText(GetDlgItem(hwnd, LABEL_IPADDR), buff, MAX_PATH);
					wstring str = buff;
					string IP_ADDR = string(str.begin(), str.end());
					hwndDialog = FindWindowExA(NULL, NULL, "CustomFirewallDialog", NULL);
					//	Check if we have to block or allow the IP
					if (MainWindow::firewall.IsIPBlocked(IP_ADDR) == TRUE)
					{
						//	Add to potential allow list.
						NetworkCTRLDialog::SetSTATICText(RULETODELETE_LABEL, IP_ADDR, hwndDialog);
					}
					else
					{
						//	Add to potential block list.
						SetWindowTextA(GetDlgItem(hwndDialog, IPADDR_TEXTBOX), IP_ADDR.c_str());
					}
					PostMessage(hwnd, WM_CLOSE, 0, 0);
				}
				else
				{
					//	Dialog already opened
					SetForegroundWindow(hwndDialog);

					//	Give the window some delay time.
					Sleep(800);

					//	SET IPADDR IN TEXTBOX
					TCHAR buff[MAX_PATH];
					GetWindowText(GetDlgItem(hwnd, LABEL_IPADDR), buff, MAX_PATH);
					wstring str = buff;
					string IP_ADDR = string(str.begin(), str.end());
					hwndDialog = FindWindowExA(NULL, NULL, "CustomFirewallDialog", NULL);
					//	Check if we have to block or allow the IP
					if (MainWindow::firewall.IsIPBlocked(IP_ADDR) == TRUE)
					{
						//	Add to potential allow list.
						NetworkCTRLDialog::SetSTATICText(RULETODELETE_LABEL, IP_ADDR, hwndDialog);
					}
					else
					{
						//	Add to potential block list.
						SetWindowTextA(GetDlgItem(hwndDialog, IPADDR_TEXTBOX), IP_ADDR.c_str());
					}
					PostMessage(hwnd, WM_CLOSE, 0, 0);
				}
				break;
			}
			default:
				break;
			}
			break;
		}
		case WM_CLOSE:
		{
			CloseWindow(hwnd);
			DestroyWindow(hwnd);
			break;
		}
		case WM_DESTROY:
		{
			PostQuitMessage(0);
			break;
		}
		default:
			return DefWindowProc(hwnd, msg, wParam, lParam);
		}
	}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	BOOL FirstRun = FALSE;
	SoftwareInstall soft;
	if (soft.ResourceOnline() != TRUE)
	{
		int ID = MessageBoxA(NULL, "First run of software detected, do you wish to install the software first?", "IPS: Info", MB_YESNO | MB_ICONEXCLAMATION);
		switch (ID)
		{
		case IDYES:
		{
			if (soft.CreateResources() == FALSE)
				MessageBoxA(NULL, "Failed to install software, running without resources.", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
			else
			{
				MessageBoxA(NULL, "Software installed!", "IPS: Info", MB_OK | MB_ICONINFORMATION);

				//	Now restart software
				MessageBoxA(NULL, "Restarting software the right way, this time!", "IPS: Info", MB_OK | MB_ICONEXCLAMATION);
				ShellExecuteA(NULL, "open", "C:\\Program Files\\IPS\\Intrusion Protection System.exe", NULL, NULL, SW_SHOWNORMAL);
				return -1;
			}
			break;
		}
		case IDNO:
			break;
		default:
			break;
		}
	}

	if (!MainWindow::RegisterOurClass(hInstance))
		return -1;
	if (!MainWindow::CreateOurWindow(hInstance, nCmdShow))
		return -1;

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return 0;
}

//	MainWindow Functions
BOOL MainWindow::RegisterOurClass(HINSTANCE hInstance)
{
	WNDCLASSEX wc;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = MainWindow::MainWndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadIcon(NULL, IDC_HAND);
	wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
	wc.lpszMenuName = MainWindowTitle;
	wc.lpszClassName = MainWClassName;
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	if (!RegisterClassEx(&wc))
	{
		MessageBoxA(NULL, "Window Registration failed!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
	return TRUE;
}
BOOL MainWindow::CreateOurWindow(HINSTANCE hInstance, int nCmdShow)
{
	HWND hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, MainWClassName, MainWindowTitle,
		WS_OVERLAPPEDWINDOW | WS_BORDER, CW_USEDEFAULT, CW_USEDEFAULT, 450, 600, NULL,NULL, hInstance, NULL);
	if (hwnd == NULL)
	{
		MessageBoxA(NULL, "Failed to create a window!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
		return FALSE;
	}
	MainWindow::HwndParent = hwnd;
	ShowWindow(hwnd, nCmdShow);
	UpdateWindow(hwnd);
	return TRUE;
}
void MainWindow::InitializeComponents(HWND HwndMain)
{
	HwndParent = HwndMain;
	HINSTANCE hInst = (HINSTANCE)GetWindowLong(HwndMain, GWL_HINSTANCE);
	HWND hwndLabel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT(STATUSLABEL1_TITLE), WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT, 
		10,10, 50, 25, 
		HwndParent, (HMENU)STATUSLABEL1, 
		(HINSTANCE)GetWindowLong(HwndMain, GWL_HINSTANCE), NULL);

	HWND hwndLabel2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT(STATUSLABEL2_TITLE), WS_CHILD | WS_VISIBLE |WS_SYSMENU | SS_LEFT,
		70,10,60,25,
		HwndParent, (HMENU)STATUSLABEL2,
		(HINSTANCE)GetWindowLong(HwndMain, GWL_HINSTANCE), NULL);

	HWND CopyRBtn = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON", TEXT(COPYRIGHTSBTN_TITLE), WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		250, 10, 150,30,
		HwndParent, (HMENU)COPYRIGHTSBTN, 
		(HINSTANCE)GetWindowLong(HwndMain, GWL_HINSTANCE), NULL);

	HWND ConnectionsBtn = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON",
		TEXT(NETSTAT_BTN_TEXT), WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		10, 80, 200, 30,
		HwndParent, (HMENU)NETSTAT_BTN,
		(HINSTANCE)GetWindowLong(HwndMain, GWL_HINSTANCE), NULL);

	HWND WFirewallBtn = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON",
		TEXT("Windows Firewall"), WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		10, 120, 200, 30,
		HwndParent, (HMENU)WINDOWS_FIREWALLBTN,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND NetworkCTRLBtn = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON",
		TEXT("Network Control"), WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		10, 160, 200, 30,
		HwndParent, (HMENU)NETWORKCTRL_BTN,
		(HINSTANCE)GetWindowLong(HwndMain, GWL_HINSTANCE), NULL);

	HWND CustomFirewall = CreateWindowEx(WS_EX_TRANSPARENT, L"BUTTON",
		TEXT("Custom Firewall"), WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		10, 200, 200, 30,
		HwndParent, (HMENU)CUSTOMFIREWALL_BTN,
		(HINSTANCE)GetWindowLong(HwndMain, GWL_HINSTANCE), NULL);

}
void MainWindow::SetIcon(HWND HwndMain)
{
	HICON IconSmall = NULL;
	HICON IconBig = NULL;

	if ((IconSmall = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconSmall = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load small icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	if ((IconBig = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconBig = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load big icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	SendMessage(HwndMain, WM_SETICON, ICON_SMALL, (LPARAM)IconSmall);
	SendMessage(HwndMain, WM_SETICON, ICON_BIG, (LPARAM)IconBig);
}
LRESULT CALLBACK MainWindow::MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HINSTANCE hInst = (HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE);
	switch (msg)
	{
	case WM_COMMAND:
	{
		//	Window Control Notifications.
		switch (LOWORD(wParam))
		{
			//	CopyRights Button
		case COPYRIGHTSBTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
				MessageBoxA(hwnd, "Name:\t\t Intrusion Protection System(IPS)\nAuthor:\t\t Trisna Quebe\nCopyRights:\t Trisna Quebe\nLanguage:\t C++ win32\nCreation Date:\t 23-11-2017\n\nDuplicate or copy the program and it's resources is only allowed with permission of the author.", "IPS: Info", MB_OK | MB_ICONINFORMATION);
				break;
			default:
				break;
			}
			break;
			//	Netstat Statics Button
		case NETSTAT_BTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				if (NetstatDialog::DialogShown == TRUE)
				{
					MessageBoxA(hwnd, "Dialog already opened!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
					break;
				}
				else
				{
					//NetstatDialog::ShowDialog(GetDesktopWindow(), (HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE));
					NetstatDialog::DialogHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NetstatDialog::ShowDialog, NULL, NULL, &NetstatDialog::dwThreadID);
					if (!NetstatDialog::DialogHandle)
					{
						MessageBoxA(hwnd, "Failed to create thread!", "IPS: error", MB_OK | MB_ICONERROR);
						break;
					}
				}
			}
			break;
			default:
				break;
			}
			break;
			//	WindowsFirewall Button
		case WINDOWS_FIREWALLBTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				if (WindowsFirewallDialog::DialogShown == TRUE)
				{
					MessageBoxA(hwnd, "Dialog already opened!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
					break;
				}
				else
				{
					WindowsFirewallDialog::DialogHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WindowsFirewallDialog::ShowDialog, NULL, NULL, &WindowsFirewallDialog::dwThreadID);
					if (!WindowsFirewallDialog::DialogHandle)
					{
						MessageBoxA(hwnd, "Failed to create thread!", "IPS: Error", MB_OK | MB_ICONERROR);
					}
				}
			}
			break;
			default:
				break;
			}
			break;
			//	Network Control Button
		case NETWORKCTRL_BTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				if (NetworkCTRLDialog::DialogShown == TRUE)
				{
					MessageBoxA(hwnd, "Dialog already opened!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
				}
				else
				{
					NetworkCTRLDialog::DialogHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NetworkCTRLDialog::ShowDialog, NULL, NULL, &NetworkCTRLDialog::dwThreadID);
					if (!NetworkCTRLDialog::DialogHandle)
					{
						MessageBoxA(hwnd, "Failed to create thread!", "IPS: Error", MB_OK | MB_ICONERROR);
					}
				}
			}
			break;
			default:
				break;
			}
			break;
			//	Custom Firewall Button
		case CUSTOMFIREWALL_BTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				if (CustomFirewallDialog::DialogShown == TRUE)
				{
					MessageBoxA(hwnd, "Dialog already opened!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
				}
				else
				{
					CustomFirewallDialog::DialogHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CustomFirewallDialog::ShowDialog, NULL, NULL, &CustomFirewallDialog::dwThreadID);
					if (!CustomFirewallDialog::DialogHandle)
					{
						MessageBoxA(hwnd, "Failed to create thread!", "IPS: Error", MB_OK | MB_ICONERROR);
					}
				}
				break;
			}
			default:
				break;
			}
			//	Default action
		default:
			break;
		}
		break;
	}
	case WM_CREATE:
	{
		InitializeComponents(hwnd);
		SetIcon(hwnd);
		break;
	}
	case WM_CLOSE:
	{
		if (FALSE == firewall.StopFirewall())
			MessageBoxA(NULL, "Failed to stop firewall before closing!", "IPS: Error", MB_OK | MB_ICONERROR);
		DestroyWindow(hwnd);
		break;
	}
	case WM_CTLCOLORSTATIC:
	{
		HDC hdcStatic = (HDC)wParam;
		SetTextColor(hdcStatic, RGB(255, 255, 255));
		SetBkMode(hdcStatic, TRANSPARENT);
		return (LRESULT)GetStockObject(NULL_BRUSH);
	}
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		break;
	}

	//	IDK	|
	//	IDK V
	case WM_POWERBROADCAST:
	{
		switch (HIWORD(wParam))
		{
		case PBT_APMSUSPEND:
		{
			//	Computer suspending
			MessageBoxA(hwnd, "Computer suspending!", "IPS: Warning", MB_OK | MB_ICONWARNING);
			break;
		}
		default:
			break;
		}
		break;
	}
	case WM_QUERYENDSESSION:
	{
		if (lParam == 0)
		{
			//	Computer shutting down
			MessageBoxA(hwnd, "Computer shutting down!", "IPS: Warning", MB_OK | MB_ICONWARNING);
		}
		else if ((lParam * ENDSESSION_LOGOFF) == ENDSESSION_LOGOFF)
		{
			//	User logging off
			MessageBoxA(hwnd, "User logging off", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
		}
		break;
	}
	case WM_ENDSESSION:
	{
		if (wParam == TRUE)
		{
			if (lParam == ENDSESSION_CLOSEAPP)
			{
				RegisterApplicationRestart(L"RESTART", 0);
			}
		}
		break;
	}
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

//	NetstatDialog Functions
BOOL NetstatDialog::RegisterDialog(HINSTANCE hInstance)
{
	WNDCLASSEX wc;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = NetstatDialog::DialogProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadIcon(NULL, IDC_HAND);
	wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0)); // 0,0,64 ~ DARK BLUE
	wc.lpszMenuName = L"TITLE";
	wc.lpszClassName = L"NetstatDialog";
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	return RegisterClassEx(&wc);
}
BOOL NetstatDialog::StartDialog(HINSTANCE hInstance, HWND HwndParent)
{
	HWND hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, L"NetstatDialog", L"Incoming and outgoing connections.",
		WS_OVERLAPPED | WS_MINIMIZEBOX | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 850, 600, HwndParent,
		NULL, hInstance, NULL);
	if (hwnd == NULL)
	{
		MessageBoxA(NULL, "Failed to create a window!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
		return FALSE;
	}
	NetstatDialog::HwndDialog = hwnd;
	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);
	return TRUE;
}
void NetstatDialog::InitializeDialog(HWND HwndMain)
{
	HWND HwndParent = HwndMain;
	HWND Label = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT(DIALOG_LABELTEXT), WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		10, 10, 100, 25,
		HwndParent, (HMENU)DIALOG_LABEL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND Label2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT(LISTBOX_LABEL1_TEXT), WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		10, 30, 100, 25,
		HwndParent, (HMENU)LISTBOX_LABEL1,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND HwndListBox = CreateWindow(TEXT("listbox"), NULL, WS_CHILD | WS_VISIBLE | LBS_STANDARD,
		10, 50, 550, 200,
		HwndParent, (HMENU)LISTBOX_LISTENING,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND Label3 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT(LISTBOX_LABEL2_TEXT), WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		10, 280, 100, 25,
		HwndParent, (HMENU)LISTBOX_LABEL2,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND HwndListBox2 = CreateWindow(TEXT("listbox"), NULL, WS_CHILD | WS_VISIBLE | LBS_STANDARD,
		10, 300, 550, 200,
		HwndParent, (HMENU)LISTBOX_ESTABLISHED,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND HwndLabelInfo = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT(LABEL_INFO_TEXT), WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		600, 50, 100, 25,
		HwndParent, (HMENU)LABEL_INFO,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND HwndLabelInfo2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT(PROCESS_LABELTEXT), WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		680, 50, 100, 25,
		HwndParent, (HMENU)PROCESS_LABEL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND KillBtn = CreateWindowW(L"BUTTON", L"Kill Process", WS_CHILD  |WS_VISIBLE | BS_DEFPUSHBUTTON,
		600, 70, 150,30,
		HwndParent, (HMENU)KILLPROCESS_BTN,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ProcessNameLabel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"Process name:", 
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT, 
		600, 100, 200, 25,
		HwndParent, (HMENU)PROCESSNAME_LABEL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ProcessNameLabel2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"None selected.",
		WS_CHILD | WS_VISIBLE | WS_SYSMENU | SS_LEFT,
		610, 125, 200, 25,
		HwndParent, (HMENU)PROCESSNAME_INFO,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ConnInformationLabel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"Connection Information:", WS_CHILD | WS_VISIBLE | SS_LEFT,
		600, 150, 200, 25,
		HwndParent, (HMENU)CONN_INFO,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ConnInformationLabel2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", L"None selected.", WS_CHILD | WS_VISIBLE | SS_LEFT,
		610, 175, 200, 40,
		HwndParent, (HMENU)LABEL_CONN_INFO,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ScanBtn = CreateWindow(L"BUTTON", L"Get Network Statics", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		10, 500, 150, 30,
		HwndParent, (HMENU)GETNETSTATICS_BTN,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND HwndFileLoc = CreateWindow(L"BUTTON", L"File Location", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		600, 210, 150, 30,
		HwndParent, (HMENU)FILELOCATION_BTN,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
}
void NetstatDialog::SetIcon(HWND HwndMain)
{
	HICON IconSmall = NULL;
	HICON IconBig = NULL;

	if ((IconSmall = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconSmall = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load small icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	if ((IconBig = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconBig = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load big icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	SendMessage(HwndMain, WM_SETICON, ICON_SMALL, (LPARAM)IconSmall);
	SendMessage(HwndMain, WM_SETICON, ICON_BIG, (LPARAM)IconBig);
}
void* NetstatDialog::ShowDialog(HWND hwnd, HINSTANCE hInstance)
{
	if (RegisterDialog(hInstance) == FALSE)
	{
		MessageBoxA(hwnd, "Failed Register Dialog!", "IPS: Error", MB_OK | MB_ICONERROR);
		stringstream ss;
		ss << "Error code: " << GetLastError();
		string str = ss.str();
		MessageBoxA(hwnd, str.c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}
	if (StartDialog(hInstance, hwnd) == FALSE)
	{
		MessageBoxA(hwnd, "Failed to start dialog!", "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}
	NetstatDialog::DialogShown = TRUE;
	MSG msg;
	while (GetMessage(&msg, 0, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	CloseDialog();
}
void NetstatDialog::CloseDialog()
{
	NetstatDialog::DialogShown = FALSE;
	UnregisterClassA("NetstatDialog", (HINSTANCE)GetModuleHandleA("NetstatDialog"));
	TerminateThread(NetstatDialog::DialogHandle, 0);
}
LRESULT CALLBACK NetstatDialog::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HINSTANCE hInst = (HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE);
	switch (msg)
	{
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
			//	Events of the listbox (LISTENING)
		case LISTBOX_LISTENING:
			switch (HIWORD(wParam))
			{
			case LBN_DBLCLK:
				MessageBoxA(hwnd, "Item dubbelclicked (LISTENING)", "IPS: Info", MB_OK);
				break;
			case LBN_SELCHANGE:
				{
				int SelectedItem = (int)SendMessage(GetDlgItem(hwnd, LISTBOX_LISTENING), LB_GETCURSEL, 0, 0);
				TCHAR buff[MAX_PATH];
				TCHAR filename[MAX_PATH];
				SendMessage(GetDlgItem(hwnd, LISTBOX_LISTENING), LB_GETTEXT, SelectedItem, (LPARAM)buff);
				UpdateProcessID(hwnd, netstat.process_listening[SelectedItem].c_str());
				UpdateConnInfoLabel(hwnd, buff);
				HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_ALL_ACCESS, FALSE, atoi(netstat.process_listening[SelectedItem].c_str()));
				if (processHandle != NULL)
				{
					if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH) == 0)
					{
						SetWindowText(GetDlgItem(hwnd, PROCESSNAME_INFO), L"Error name");
						ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_HIDE);
						ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_SHOW);
					}
					else
					{
						wstring str(filename);
						string label_text(str.begin(), str.end());
						string text = label_text.substr(label_text.find_last_of("\\") + 1);

						SetWindowTextA(GetDlgItem(hwnd, PROCESSNAME_INFO), text.c_str());
						ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_HIDE);
						ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_SHOW);
					}
				}
				else
				{
					stringstream err;
					err << "Error process: " << GetLastError();
					SetWindowTextA(GetDlgItem(hwnd, PROCESSNAME_INFO), err.str().c_str());
					ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_HIDE);
					ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_SHOW);
				}
			}
				break;
			default:
				break;
			}
			break;
			//	Events of the listbox (ESTABLISHED)
		case LISTBOX_ESTABLISHED:
			switch (HIWORD(wParam))
			{
			case LBN_DBLCLK:
				MessageBoxA(hwnd, "Item dubbelclicked (ESTABLISHED)", "IPS: Info", MB_OK);
				break;
			case LBN_SELCHANGE:
			{
				int SelectedItem = (int)SendMessage(GetDlgItem(hwnd, LISTBOX_ESTABLISHED), LB_GETCURSEL, 0, 0);
				TCHAR buff[MAX_PATH];
				TCHAR filename[MAX_PATH];
				SendMessage(GetDlgItem(hwnd, LISTBOX_ESTABLISHED), LB_GETTEXT, SelectedItem, (LPARAM)buff);
				UpdateProcessID(hwnd, netstat.process_established[SelectedItem].c_str());
				UpdateConnInfoLabel(hwnd, buff);
				HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, atoi(netstat.process_established[SelectedItem].c_str()));
				if (processHandle != NULL)
				{
					if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH) == 0)
					{
						SetWindowText(GetDlgItem(hwnd, PROCESSNAME_INFO), L"Error name");
						ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_HIDE);
						ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_SHOW);
					}
					else
					{
						wstring str(filename);
						string label_text(str.begin(), str.end());
						string text = label_text.substr(label_text.find_last_of("\\") + 1);

						SetWindowTextA(GetDlgItem(hwnd, PROCESSNAME_INFO), text.c_str());
						ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_HIDE);
						ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_SHOW);
					}
				}
				else
				{
					stringstream err;
					err << "Error process: " << GetLastError();
					SetWindowTextA(GetDlgItem(hwnd, PROCESSNAME_INFO), err.str().c_str());
					ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_HIDE);
					ShowWindow(GetDlgItem(hwnd, PROCESSNAME_INFO), SW_SHOW);
				}
			}
			break;
			default:
				break;
			}
			break;
			//	Events of the button "Get Networkstatics"
		case GETNETSTATICS_BTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				SendMessage(GetDlgItem(hwnd, LISTBOX_ESTABLISHED), LB_RESETCONTENT, 0, 0);
				SendMessage(GetDlgItem(hwnd, LISTBOX_LISTENING), LB_RESETCONTENT, 0, 0);

				netstat.GET_NETWORKSTATICS_LISTENING(GetDlgItem(hwnd, LISTBOX_LISTENING));
				netstat.GET_NETWORKSTATICS_ESTABLISHED(GetDlgItem(hwnd, LISTBOX_ESTABLISHED));
			}
			break;
			default:
				break;
			}
			break;
			//	Events of the button "Kill Process"
		case KILLPROCESS_BTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				DWORD ProcessID;
				//	Getting Label text
				char buffer[65536];
				int txtlen = GetWindowTextLength(GetDlgItem(hwnd, PROCESS_LABEL));
				GetWindowTextA(GetDlgItem(hwnd, PROCESS_LABEL), buffer, txtlen +1);
				string pid = buffer;
				if ((ProcessID = atoi(pid.c_str())) != 0)
				{
					if (KillProcess(ProcessID) == FALSE)
					{
						MessageBoxA(hwnd, "Failed to kill the process!", "IPS: Error", MB_OK | MB_ICONASTERISK);
					}
					else
					{
						MessageBoxA(hwnd, "Process succesfully killed!", "IPS: Info", MB_OK | MB_ICONINFORMATION);

						SendMessage(GetDlgItem(hwnd, LISTBOX_ESTABLISHED), LB_RESETCONTENT, 0, 0);
						SendMessage(GetDlgItem(hwnd, LISTBOX_LISTENING), LB_RESETCONTENT, 0, 0);

						netstat.GET_NETWORKSTATICS_LISTENING(GetDlgItem(hwnd, LISTBOX_LISTENING));
						netstat.GET_NETWORKSTATICS_ESTABLISHED(GetDlgItem(hwnd, LISTBOX_ESTABLISHED));
					}
				}
				else 
				{
					MessageBoxA(hwnd, "Failed to get processID", "Info", MB_OK);
				}
			}
			break;
			default:
				break;
			}
			break;
			//	Events of the button "File Location"
		case FILELOCATION_BTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				char buffer[65536];
				int txtlen = GetWindowTextLength(GetDlgItem(hwnd, PROCESS_LABEL));
				GetWindowTextA(GetDlgItem(hwnd, PROCESS_LABEL), buffer, txtlen + 1);
				string pid = buffer;
				DWORD ProcessID;
				if ((ProcessID = atoi(pid.c_str())) != 0)
				{
					HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessID);
					if (!hProcess)
					{
						MessageBoxA(hwnd, "Failed to open process!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
					}
					else
					{
						TCHAR filename[MAX_PATH];
						if (GetModuleFileNameEx(hProcess, NULL, filename, MAX_PATH) == 0)
						{
							MessageBoxA(hwnd, "Failed to get module filename!", "IPS: Error", MB_OK | MB_ICONERROR);
						}
						else
						{
							//	Retrieve only the directory
							wstring str(filename);
							string file(str.begin(), str.end());
							string location = file.substr(0, file.find_last_of("\\"));

							//	Open in explorer
							ShellExecuteA(NULL, "open", location.c_str(), NULL, NULL, SW_SHOWDEFAULT);
						}
					}
				}
				else
				{
					MessageBoxA(hwnd, "Failed to get process location!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
				}
			}
				break;
			default:
				break;
			}
			break;
			//	Default action
		default:
			break;
		}
		break;
	case WM_CREATE:
		{
			//	Initializing controls for dialog window
			InitializeDialog(hwnd);
			SetIcon(hwnd);
		}
		break;
	case WM_PAINT:
		{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);
		if (LoadAndBlitBitMap(TEXT("C:\\Program Files\\IPS\\Images\\IPS-Computer.bmp"), hdc) == FALSE)
		{
			if (LoadAndBlitBitMap(TEXT("IPS-Computer.bmp"), hdc) == FALSE)
			{
				MessageBoxA(hwnd, "Loading Image Failed!", "IPS: Error", MB_OK | MB_ICONERROR);
			}
		}
		EndPaint(hwnd, &ps);
		}
		break;
	case WM_CLOSE:
		{
		DestroyWindow(hwnd);
		}
		break;
	case WM_DESTROY:
		{
			PostQuitMessage(0);
		}
		break;
	case WM_CTLCOLORSTATIC:
		{
		HDC hdcStatic = (HDC)wParam;
		SetTextColor(hdcStatic, RGB(255, 255, 255));
		SetBkMode(hdcStatic, TRANSPARENT);
		return (LONG)GetStockObject(NULL_BRUSH);
	}
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

void NetstatDialog::UpdateProcessID(HWND hwndParent, string text)
{
	SetWindowTextA(GetDlgItem(hwndParent, PROCESS_LABEL), text.c_str());
	ShowWindow(GetDlgItem(hwndParent, PROCESS_LABEL), SW_HIDE);
	ShowWindow(GetDlgItem(hwndParent, PROCESS_LABEL), SW_SHOW);
}
void NetstatDialog::UpdateConnInfoLabel(HWND hwndParent, TCHAR* buff)
{
	SetWindowText(GetDlgItem(hwndParent, LABEL_CONN_INFO), buff);
	ShowWindow(GetDlgItem(hwndParent, LABEL_CONN_INFO), SW_HIDE);
	ShowWindow(GetDlgItem(hwndParent, LABEL_CONN_INFO), SW_SHOW);
}
BOOL NetstatDialog::KillProcess(DWORD ProcessID)
{
	DWORD dwDesiredAcces = PROCESS_TERMINATE;
	HANDLE hProcess = OpenProcess(dwDesiredAcces, FALSE, ProcessID);
	if (hProcess == FALSE)
		return FALSE;
	BOOL result = TerminateProcess(hProcess, 0);

	CloseHandle(hProcess);
	return TRUE;
}
BOOL NetstatDialog::LoadAndBlitBitMap(LPCWSTR szFilename, HDC hWinDC)
{
	System::String^ str = gcnew System::String(szFilename);
	if (File::Exists(str) == FALSE)
		return FALSE;
	//	Loading the image file
	HBITMAP hBitmap;
	hBitmap = (HBITMAP)::LoadImage(NULL, szFilename, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
	//	Verifiy that the bitmap was loaded
	if (hBitmap == NULL)
	{
		MessageBoxA(NULL, "Failed to load image!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	//	Create a device context that is compatible with the window
	HDC hLocalDC;
	hLocalDC = CreateCompatibleDC(hWinDC);
	//	Verify that the device context was created
	if (hLocalDC == NULL)
	{
		MessageBoxA(NULL, "Failed to CreateCompatibleDC() !!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	//	Get the bitmap's parameters and verify the get
	BITMAP qBitmap;
	int iResult = GetObject(reinterpret_cast<HGDIOBJ>(hBitmap), sizeof(BITMAP),
		reinterpret_cast<LPVOID>(&qBitmap));
	if (!iResult)
	{
		MessageBoxA(NULL, "GetObject failed!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
	
	//	Select the loaded bitmap into the device context
	HBITMAP hOldBmp = (HBITMAP)SelectObject(hLocalDC, hBitmap);
	if (hOldBmp == NULL)
	{
		MessageBoxA(NULL, "Select Object failed!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	//	Blit the dc which holds the bitmap onto the window's dc
	BOOL qRetBlit = BitBlt(hWinDC, 550, 250, qBitmap.bmWidth, qBitmap.bmHeight,
		hLocalDC, 0, 0, SRCCOPY);
	if (!qRetBlit)
	{
		MessageBoxA(NULL, "Blit failed!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	// Unitialize and deallocate resources
	::SelectObject(hLocalDC, hOldBmp);
	::DeleteDC(hLocalDC);
	::DeleteObject(hBitmap);
	return TRUE;
}

//	WindowsFirewallDialog Functions
BOOL WindowsFirewallDialog::RegisterDialog(HINSTANCE hInstance)
{
	WNDCLASSEX wc;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = WindowsFirewallDialog::DialogProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadIcon(NULL, IDC_HAND);
	wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
	wc.lpszMenuName = L"TITLE";
	wc.lpszClassName = L"WindowsFirewallDialog";
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	return RegisterClassEx(&wc);
}
BOOL WindowsFirewallDialog::StartDialog(HINSTANCE hInstance, HWND HwndParent)
{
	HWND hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, L"WindowsFirewallDialog", L"Windows Firewall Information",
		WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 600, HwndParent,
		NULL, hInstance, NULL);
	if (hwnd == NULL)
	{
		MessageBoxA(NULL, "Failed to create a window!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
		return FALSE;
	}
	NetstatDialog::HwndDialog = hwnd;
	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);
	return TRUE;
}
void WindowsFirewallDialog::InitializeDialog(HWND HwndParent)
{
	HWND InfoLabel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Windows Firewall Information:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU | WS_BORDER, 10, 10, 200, 25, 
		HwndParent, (HMENU)LABELWFIREWALL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ProfileDomain = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Domain Profile:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		200, 50, 200, 25,
		HwndParent, (HMENU)DOMAINPROFILELBL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND ProfilePrivate = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Private Profile:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		500, 50, 200, 25,
		HwndParent, (HMENU)PRIVATEPROFILELBL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND ProfilePublic = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Public Profile:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		800, 50, 200, 25,
		HwndParent, (HMENU)PUBLICPROFILELBL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	//	Information labels
	HWND FirewallState = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Firewall State:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		10, 75, 200, 25,
		HwndParent, (HMENU)L"FIREWALLSTATE",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND BlockInbound = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Block all inbound traffic:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		10, 100, 200, 25,
		HwndParent, (HMENU)L"BLOCKINBOUND",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND UnicastRespons = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("UnicastRespons-MultiBCast:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,	10, 125, 200, 25,
		HwndParent, (HMENU)L"UNICASTRESPONS",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND DefInboundAction = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Default Inbound Action:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		10, 150, 200, 25,
		HwndParent, (HMENU)L"DEFINBOUNDAC",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND DefOutboundAction = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Default Outbound Action:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		10, 175, 200, 25,
		HwndParent, (HMENU)L"DefOutBoundAc",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND Notifications = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Notifications:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		10, 200, 200, 25,
		HwndParent, (HMENU)L"Notifications",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	//	Data labels
	HWND FirewallState1 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown1"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		220, 75, 200, 25,
		HwndParent, (HMENU)FWSTATE1,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND FirewallState2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown2"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		520, 75, 200, 25,
		HwndParent, (HMENU)FWSTATE2,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND FirewallState3 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown3"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		820, 75, 200, 25,
		HwndParent, (HMENU)FWSTATE3,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND BlockInbound1 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown1"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		220, 100, 200, 25,
		HwndParent, (HMENU)BLOCKINBOUND1,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND BlockInbound2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown2"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		520, 100, 200, 25,
		HwndParent, (HMENU)BLOCKINBOUND2,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND BlockInbound3 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown3"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		820, 100, 200, 25,
		HwndParent, (HMENU)BLOCKINBOUND3,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND UnicastRes1 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown1"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		220, 125, 200, 25,
		HwndParent, (HMENU)UNICASTRES1,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND UnicastRes2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown2"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		520, 125, 200, 25,
		HwndParent, (HMENU)UNICASTRES2,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND UnicastRes3 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown3"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		820, 125, 200, 25,
		HwndParent, (HMENU)UNICASTRES3,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND DefInboundAc1 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown1"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		220, 150, 200, 25,
		HwndParent, (HMENU)DEFINBOUNDAC1,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND DefInboundAc2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown2"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		520, 150, 200, 25,
		HwndParent, (HMENU)DEFINBOUNDAC2,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND DefInboundAc3 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown3"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		820, 150, 200, 25,
		HwndParent, (HMENU)DEFINBOUNDAC3,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND DefOutboundAction1 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown1"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		220, 175, 200, 25,
		HwndParent, (HMENU)DEFOUTBOUNDAC1,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND DefOutboundAction2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown2"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		520, 175, 200, 25,
		HwndParent, (HMENU)DEFOUTBOUNDAC2,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND DefOutboundAction3 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown3"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		820, 175, 200, 25,
		HwndParent, (HMENU)DEFOUTBOUNDAC3,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND Notifications1 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown1"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		220, 200, 200, 25,
		HwndParent, (HMENU)NOTIFICATIONS1,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND Notifications2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown2"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		520, 200, 200, 25,
		HwndParent, (HMENU)NOTIFICATIONS2,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	HWND Notifications3 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown3"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		820, 200, 200, 25,
		HwndParent, (HMENU)NOTIFICATIONS3,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
}
void WindowsFirewallDialog::SetIcon(HWND HwndMain)
{
	HICON IconSmall = NULL;
	HICON IconBig = NULL;

	if ((IconSmall = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconSmall = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load small icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	if ((IconBig = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconBig = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load big icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	SendMessage(HwndMain, WM_SETICON, ICON_SMALL, (LPARAM)IconSmall);
	SendMessage(HwndMain, WM_SETICON, ICON_BIG, (LPARAM)IconBig);
}
void *WindowsFirewallDialog::ShowDialog(HWND hwnd, HINSTANCE hInstance)
{
	if (RegisterDialog(hInstance) == FALSE)
	{
		MessageBoxA(hwnd, "Failed Register Dialog!", "IPS: Error", MB_OK | MB_ICONERROR);
		stringstream ss;
		ss << "Error code: " << GetLastError();
		string str = ss.str();
		MessageBoxA(hwnd, str.c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}
	if (StartDialog(hInstance, hwnd) == FALSE)
	{
		MessageBoxA(hwnd, "Failed to start dialog!", "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}
	WindowsFirewallDialog::DialogShown = TRUE;
	MSG msg;
	while (GetMessage(&msg, 0, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	CloseDialog();
}
void WindowsFirewallDialog::CloseDialog()
{
	WindowsFirewallDialog::DialogShown = FALSE;
	UnregisterClassA("WindowsFirewallDialog", (HINSTANCE)GetModuleHandleA("WindowsFirewallDialog"));
	TerminateThread(WindowsFirewallDialog::DialogHandle, 0);
}
LRESULT CALLBACK WindowsFirewallDialog::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CREATE:
	{
		//	Initialize components for dialog window
		WindowsFirewallDialog::InitializeDialog(hwnd);
		SetIcon(hwnd);
		//	Retrieve information for the labels
		if (WindowsFirewallDialog::GetFirewallInformation(hwnd) == FALSE)
		{
			MessageBoxA(hwnd, "Failed to retrieve firewall settings!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
		break;
	}
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);

		if (LoadAndBlitBitMap(TEXT("C:\\Program Files\\IPS\\Images\\IPS-Firewall.bmp"), hdc) == FALSE)
		{
			if (LoadAndBlitBitMap(TEXT("IPS-Firewall.bmp"), hdc) == FALSE)
			{
				MessageBoxA(hwnd, "Loading Image Failed!", "IPS: Error", MB_OK | MB_ICONERROR);
			}
		}
		EndPaint(hwnd, &ps);
		break;
	}
	case WM_CLOSE:
	{
		DestroyWindow(hwnd);
		break;
	}
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		break;
	}
	case WM_CTLCOLORSTATIC:
	{
		HDC hdcStatic = (HDC)wParam;
		SetTextColor(hdcStatic, RGB(255, 255, 255));
		SetBkMode(hdcStatic, TRANSPARENT);
		return (LRESULT)GetStockObject(NULL_BRUSH);
	}
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

BOOL WindowsFirewallDialog::GetFirewallInformation(HWND hwnd)
{
	INetFwPolicy2 *pNetFwPolicy2 = NULL;
	HRESULT hr = S_OK;
	HRESULT hrComInit = S_OK;

	NET_FW_PROFILE_TYPE2 ProfileTypeDomain = NET_FW_PROFILE2_DOMAIN;
	NET_FW_PROFILE_TYPE2 ProfileTypePrivate = NET_FW_PROFILE2_PRIVATE;
	NET_FW_PROFILE_TYPE2 ProfileTypePublic = NET_FW_PROFILE2_PUBLIC;

	//	Initialize COM
	hrComInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	if (hrComInit != RPC_E_CHANGED_MODE)
	{
		if (FAILED(hr))
		{
			stringstream ss;
			ss << "CoInitializeEx failed! Error: " << GetLastError();
			MessageBoxA(hwnd, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
			goto Cleanup;
		}
	}

	hr = WFCOMInitialize(&pNetFwPolicy2);
	if (FAILED(hr))
	{
		goto Cleanup;
	}

	VARIANT_BOOL bIsEnabled = FALSE;
	NET_FW_ACTION action;

	if (SUCCEEDED(pNetFwPolicy2->get_FirewallEnabled(ProfileTypeDomain, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(FWSTATE1, hwnd, "Enabled");
		else
			SetLabelText(FWSTATE1, hwnd, "Disabled");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_FirewallEnabled(ProfileTypePrivate, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(FWSTATE2, hwnd, "Enabled");
		else
			SetLabelText(FWSTATE2, hwnd, "Disabled");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_FirewallEnabled(ProfileTypePublic, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(FWSTATE3, hwnd, "Enabled");
		else
			SetLabelText(FWSTATE3, hwnd, "Disabled");
	}

	if (SUCCEEDED(pNetFwPolicy2->get_BlockAllInboundTraffic(ProfileTypeDomain, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(BLOCKINBOUND1, hwnd, "Enabled");
		else
			SetLabelText(BLOCKINBOUND1, hwnd, "Disabled");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_BlockAllInboundTraffic(ProfileTypePrivate, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(BLOCKINBOUND2, hwnd, "Enabled");
		else
			SetLabelText(BLOCKINBOUND2, hwnd, "Disabled");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_BlockAllInboundTraffic(ProfileTypePublic, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(BLOCKINBOUND3, hwnd, "Enabled");
		else
			SetLabelText(BLOCKINBOUND3, hwnd, "Disabled");
	}

	if (SUCCEEDED(pNetFwPolicy2->get_NotificationsDisabled(ProfileTypeDomain, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(NOTIFICATIONS1, hwnd, "Disabled");
		else
			SetLabelText(NOTIFICATIONS1, hwnd, "Enabled");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_NotificationsDisabled(ProfileTypePrivate, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(NOTIFICATIONS2, hwnd, "Disabled");
		else
			SetLabelText(NOTIFICATIONS2, hwnd, "Enabled");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_NotificationsDisabled(ProfileTypePublic, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(NOTIFICATIONS3, hwnd, "Disabled");
		else
			SetLabelText(NOTIFICATIONS3, hwnd, "Enabled");
	}

	if (SUCCEEDED(pNetFwPolicy2->get_UnicastResponsesToMulticastBroadcastDisabled(ProfileTypeDomain, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(UNICASTRES1, hwnd, "Disabled");
		else
			SetLabelText(UNICASTRES1, hwnd, "Enabled");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_UnicastResponsesToMulticastBroadcastDisabled(ProfileTypePrivate, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(UNICASTRES2, hwnd, "Disabled");
		else
			SetLabelText(UNICASTRES2, hwnd, "Enabled");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_UnicastResponsesToMulticastBroadcastDisabled(ProfileTypePublic, &bIsEnabled)))
	{
		if (bIsEnabled == VARIANT_TRUE)
			SetLabelText(UNICASTRES3, hwnd, "Disabled");
		else
			SetLabelText(UNICASTRES3, hwnd, "Enabled");
	}

	if (SUCCEEDED(pNetFwPolicy2->get_DefaultInboundAction(ProfileTypeDomain, &action)))
	{
		if (action == NET_FW_ACTION_ALLOW)
			SetLabelText(DEFINBOUNDAC1, hwnd, "Allow");
		else
			SetLabelText(DEFINBOUNDAC1, hwnd, "Block");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_DefaultInboundAction(ProfileTypePrivate, &action)))
	{
		if (action == NET_FW_ACTION_ALLOW)
			SetLabelText(DEFINBOUNDAC2, hwnd, "Allow");
		else
			SetLabelText(DEFINBOUNDAC2, hwnd, "Block");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_DefaultInboundAction(ProfileTypePublic, &action)))
	{
		if (action == NET_FW_ACTION_ALLOW)
			SetLabelText(DEFINBOUNDAC3, hwnd, "Allow");
		else
			SetLabelText(DEFINBOUNDAC3, hwnd, "Block");
	}

	if (SUCCEEDED(pNetFwPolicy2->get_DefaultOutboundAction(ProfileTypeDomain, &action)))
	{
		if (action == NET_FW_ACTION_ALLOW)
			SetLabelText(DEFOUTBOUNDAC1, hwnd, "Allow");
		else
			SetLabelText(DEFOUTBOUNDAC1, hwnd, "Block");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_DefaultOutboundAction(ProfileTypePrivate, &action)))
	{
		if (action == NET_FW_ACTION_ALLOW)
			SetLabelText(DEFOUTBOUNDAC2, hwnd, "Allow");
		else
			SetLabelText(DEFOUTBOUNDAC2, hwnd, "Block");
	}
	if (SUCCEEDED(pNetFwPolicy2->get_DefaultOutboundAction(ProfileTypePublic, &action)))
	{
		if (action == NET_FW_ACTION_ALLOW)
			SetLabelText(DEFOUTBOUNDAC3, hwnd, "Allow");
		else
			SetLabelText(DEFOUTBOUNDAC3, hwnd, "Block");
	}

Cleanup:
	// Release INetFwPolicy2
	if (pNetFwPolicy2 != NULL)
	{
		pNetFwPolicy2->Release();
	}
	// Uninitialize COM.
	if (SUCCEEDED(hrComInit))
	{
		CoUninitialize();
	}
	if (FAILED(hr))
		return FALSE;
	return TRUE;
}
HRESULT WindowsFirewallDialog::WFCOMInitialize(INetFwPolicy2** ppNetFwPolicy2)
{
	HRESULT hr = S_OK;
	hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER,
		__uuidof(INetFwPolicy2), (void**)ppNetFwPolicy2);
	if (FAILED(hr))
	{
		stringstream ss;
		ss << "CoCreateInstance failed for INetFwPolicy2! Error: " << hr;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		goto Cleanup;
	}
Cleanup:
	return hr;
}
void WindowsFirewallDialog::SetLabelText(int LabelID, HWND hwnd, string text)
{
	SetWindowTextA(GetDlgItem(hwnd, (int)LabelID), text.c_str());
	SendMessageA(GetDlgItem(hwnd, (int)LabelID), WM_SETTEXT, 0, (LPARAM)text.c_str());
}
BOOL WindowsFirewallDialog::LoadAndBlitBitMap(LPCWSTR szFilename, HDC hWinDC)
{
	System::String^ str = gcnew System::String(szFilename);
	if (File::Exists(str) == FALSE)
		return FALSE;

	//	Loading the image file
	HBITMAP hBitmap;
	hBitmap = (HBITMAP)::LoadImage(NULL, szFilename, IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE);
	//	Verifiy that the bitmap was loaded
	if (hBitmap == NULL)
	{
		MessageBoxA(NULL, "Failed to load image!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	//	Create a device context that is compatible with the window
	HDC hLocalDC;
	hLocalDC = CreateCompatibleDC(hWinDC);
	//	Verify that the device context was created
	if (hLocalDC == NULL)
	{
		MessageBoxA(NULL, "Failed to CreateCompatibleDC() !!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	//	Get the bitmap's parameters and verify the get
	BITMAP qBitmap;
	int iResult = GetObject(reinterpret_cast<HGDIOBJ>(hBitmap), sizeof(BITMAP),
		reinterpret_cast<LPVOID>(&qBitmap));
	if (!iResult)
	{
		MessageBoxA(NULL, "GetObject failed!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	//	Select the loaded bitmap into the device context
	HBITMAP hOldBmp = (HBITMAP)SelectObject(hLocalDC, hBitmap);
	if (hOldBmp == NULL)
	{
		MessageBoxA(NULL, "Select Object failed!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	//	Blit the dc which holds the bitmap onto the window's dc
	BOOL qRetBlit = BitBlt(hWinDC, 10, 250, qBitmap.bmWidth, qBitmap.bmHeight,
		hLocalDC, 0, 0, SRCCOPY);
	if (!qRetBlit)
	{
		MessageBoxA(NULL, "Blit failed!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	// Unitialize and deallocate resources
	::SelectObject(hLocalDC, hOldBmp);
	::DeleteDC(hLocalDC);
	::DeleteObject(hBitmap);
	return TRUE;
}

//	NetworkCTRLDialog Functions
BOOL NetworkCTRLDialog::RegisterDialog(HINSTANCE hInstance)
{
	WNDCLASSEX wc;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = NetworkCTRLDialog::DialogProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadIcon(NULL, IDC_HAND);
	wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
	wc.lpszMenuName = L"TITLE";
	wc.lpszClassName = L"NetworkCTRLDialog";
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	return RegisterClassEx(&wc);
}
BOOL NetworkCTRLDialog::StartDialog(HINSTANCE hInstance, HWND HwndParent)
{
	HWND hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, L"NetworkCTRLDialog", L"Network Control",
		WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 900, 600, HwndParent,
		NULL, hInstance, NULL);
	if (hwnd == NULL)
	{
		MessageBoxA(NULL, "Failed to create a window!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
		return FALSE;
	}
	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);
	return TRUE;
}
void NetworkCTRLDialog::InitializeDialog(HWND HwndParent)
{
	HWND Listbox_label = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Online Friendly Devices:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		10, 25, 200, 25,
		HwndParent, (HMENU)LABEL_ONLINEDEV,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ListOnline_Devices = CreateWindow(TEXT("listbox"), NULL, WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL |WS_BORDER  | LBS_HASSTRINGS,
		10, 50, 400, 200,
		HwndParent, (HMENU)LISTBOX_ONLINEDEV,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ListBox_label2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown Devices:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		10, 250, 200, 25,
		HwndParent, (HMENU)LABEL_UNKNOWNDEV,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ListUnknown_Devices = CreateWindow(TEXT("listbox"), NULL, WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL | WS_BORDER,
		10, 275, 400, 200,
		HwndParent, (HMENU)LISTBOX_UNKNOWNDEV,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND Listbox_label3 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Allowed devices: (Friendly-Device.ips file)"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		450, 25, 300, 25,
		HwndParent, (HMENU)LABEL_FILELISTBOX,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND FileListbox = CreateWindow(TEXT("listbox"), NULL, WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL | WS_BORDER,
		450, 50, 400, 200,
		HwndParent, (HMENU)LISTBOX_FILE,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND Label1 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Add Friendly Device:"), WS_CHILD | WS_VISIBLE |SS_LEFT | WS_SYSMENU,
		450, 275, 300, 25,
		HwndParent, (HMENU)LABEL_ADDDEVICES,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	
	HWND FRIENDLYNAMELABEL = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Friendly Name:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		460, 300, 200, 20,
		HwndParent, (HMENU)"LABEL_FRIENDLYNAME",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND MACADDRLABEL = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("MAC Address:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		460, 320, 200, 20,
		HwndParent, (HMENU)"LABEL_MACADDR",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND POT_IPADDRLABEL = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("IP Address:"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		460, 340, 200, 20,
		HwndParent, (HMENU)"LABEL_IPADDR",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND EditText = CreateWindow(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL | ES_WANTRETURN,
		600, 300, 200, 20,
		HwndParent, (HMENU)EDIT_FRIENDLYNAME,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND EditText2 = CreateWindow(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL | ES_WANTRETURN,
		600, 320, 200, 20,
		HwndParent, (HMENU)EDIT_MACADDR,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND EditText3 = CreateWindow(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL | ES_WANTRETURN,
		600, 340, 200, 20,
		HwndParent, (HMENU)EDIT_IPADDR,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND BTN_ADD = CreateWindow(L"BUTTON", L"Add Device", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		650, 360, 150, 30,
		HwndParent, (HMENU)BTN_ADDFRIENDLYDEV,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND DelDevLabel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Delete Friendly Device: "), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		450, 400, 200, 20,
		HwndParent, (HMENU)"",
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND DelInfoLabel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("NONE_SELECTED"), WS_CHILD | WS_VISIBLE | SS_LEFT | WS_SYSMENU,
		460, 420, 400, 20,
		HwndParent, (HMENU)SELECTED_DEV,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND DeleteBtn = CreateWindow(L"BUTTON", L"Delete Device", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		650, 440, 150, 30,
		HwndParent, (HMENU)BTN_DELFRIENDLYDEV,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
}
void NetworkCTRLDialog::SetIcon(HWND HwndMain)
{
	HICON IconSmall = NULL;
	HICON IconBig = NULL;

	if ((IconSmall = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconSmall = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load small icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	if ((IconBig = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconBig = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load big icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	SendMessage(HwndMain, WM_SETICON, ICON_SMALL, (LPARAM)IconSmall);
	SendMessage(HwndMain, WM_SETICON, ICON_BIG, (LPARAM)IconBig);
}
void *NetworkCTRLDialog::ShowDialog(HWND hwnd, HINSTANCE hInstance)
{
	if (RegisterDialog(hInstance) == FALSE)
	{
		MessageBoxA(hwnd, "Failed Register Dialog!", "IPS: Error", MB_OK | MB_ICONERROR);
		stringstream ss;
		ss << "Error code: " << GetLastError();
		string str = ss.str();
		MessageBoxA(hwnd, str.c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}
	if (StartDialog(hInstance, hwnd) == FALSE)
	{
		MessageBoxA(hwnd, "Failed to start dialog!", "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}
	NetworkCTRLDialog::DialogShown = TRUE;
	NetworkCTRLDialog::HwndMain = hwnd;
	MSG msg;
	while (GetMessage(&msg, 0, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	CloseDialog();
	return 0;
}
void NetworkCTRLDialog::CloseDialog()
{
	NetworkCTRLDialog::DialogShown = FALSE;
	UnregisterClass(L"NetworkCTRLDialog", (HINSTANCE)GetModuleHandle(L"NetworkCTRLDialog"));
	TerminateThread(NetworkCTRLDialog::DialogHandle, 0);
}
LRESULT CALLBACK NetworkCTRLDialog::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CREATE:
	{
		InitializeDialog(hwnd);
		SetIcon(hwnd);
		LoopFileIndex(hwnd);
		OnlineDevThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NetworkCTRLDialog::LoopingOnlineDevices, (LPVOID)hwnd, NULL, &dwOnlineDevThreadID);
		if (!OnlineDevThread)
		{
			MessageBoxA(hwnd, "Failed to start thread! [LoopingOnlineDevices()]", "IPS: Error", MB_OK | MB_ICONERROR);
			break;
		}
		UnknownDevThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)NetworkCTRLDialog::LoopingUnknownDevices, (LPVOID)hwnd, NULL, &dwUnknownDevThread);
		if (!UnknownDevThread)
		{
			MessageBoxA(NULL, "Failed to start thread! [LoopingUnknownDevices()]", "IPS: Error", MB_OK | MB_ICONERROR);
			break;
		}
		break;
	}
	case WM_CTLCOLORSTATIC:
	{
		HDC hdcStatic = (HDC)wParam;
		SetTextColor(hdcStatic, RGB(255, 255, 255));
		SetBkMode(hdcStatic, TRANSPARENT);
		return (LRESULT)GetStockObject(NULL_BRUSH);
	}
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		break;
	}
	case WM_COMMAND:
	{
		switch (LOWORD(wParam))
		{
		case LISTBOX_UNKNOWNDEV:
			switch (HIWORD(wParam))
			{
			case LBN_DBLCLK:
			{
				if (ActionWindow2::WindowOpen == TRUE || ActionWindow::WindowOpen == TRUE)
				{
					MessageBoxA(hwnd, "A ActionWindow is already opened!", "IPS: Warning", MB_OK | MB_ICONWARNING);
					break;
				}
				HWND ListBox = GetDlgItem(hwnd, LISTBOX_UNKNOWNDEV);
				int SelItem = SendMessage(ListBox, LB_GETCURSEL, 0, 0);
				TCHAR buff[MAX_PATH];
				SendMessage(ListBox, LB_GETTEXT, SelItem, (LPARAM)buff);
				wstring str = buff;
				string device = string(str.begin(), str.end());
				ActionWindow::ShowActionWindow(hwnd, (HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE), device);
				break;
			}
			default:
				break;
			}
			break;
		case LISTBOX_ONLINEDEV:
			switch (HIWORD(wParam))
			{
			case LBN_DBLCLK:
			{
				if (ActionWindow::WindowOpen == TRUE || ActionWindow2::WindowOpen == TRUE)
				{
					MessageBoxA(hwnd, "A ActionWindow is already opened!", "IPS: Warning", MB_OK | MB_ICONWARNING);
					break;
				}
				HWND Listbox = GetDlgItem(hwnd, LISTBOX_ONLINEDEV);
				int SelItem = SendMessage(Listbox, LB_GETCURSEL, 0, 0);
				TCHAR buff[MAX_PATH];
				SendMessage(Listbox, LB_GETTEXT, SelItem, (LPARAM)buff);
				wstring str = buff;
				string device = string(str.begin(), str.end());
				ActionWindow2::ShowActionWindow(hwnd, (HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE),device);
				break;
			}
			default:
				break;
			}
			break;
		case LISTBOX_FILE:
			switch (HIWORD(wParam))
			{
			case LBN_SELCHANGE:
			{
				TCHAR buff[MAX_PATH];
				HWND Listbox = GetDlgItem(hwnd, LISTBOX_FILE);
				HWND LabelSelectedDev = GetDlgItem(hwnd, SELECTED_DEV);
				int SelItem = SendMessage(Listbox, LB_GETCURSEL, 0, 0);
				SendMessage(Listbox, LB_GETTEXT, (WPARAM)SelItem, (LPARAM)buff);
				wstring str = buff;
				string item = string(str.begin(), str.end());
				SetSTATICText(SELECTED_DEV, item, hwnd);
				break;
			}
			default:
				break;
			}
			break;
		case BTN_ADDFRIENDLYDEV:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				TCHAR FriendlyDev[MAX_PATH];
				TCHAR MacAddr[MAX_PATH];
				TCHAR IpAddr[MAX_PATH];
				HWND Edit_FriendlyDev = GetDlgItem(hwnd, EDIT_FRIENDLYNAME);
				HWND Edit_MacAddr = GetDlgItem(hwnd, EDIT_MACADDR);
				HWND Edit_IpAddr = GetDlgItem(hwnd, EDIT_IPADDR);
				//	Get the strings of edittext
				GetWindowText(Edit_FriendlyDev, FriendlyDev, MAX_PATH);
				GetWindowText(Edit_MacAddr, MacAddr, MAX_PATH);
				GetWindowText(Edit_IpAddr, IpAddr, MAX_PATH);
				//	Converting TCHAR to std::wstring
				wstring str1 = FriendlyDev;
				wstring str2 = MacAddr;
				wstring str3 = IpAddr;
				//	Convert std::wstring to std::string
				string FD = string(str1.begin(), str1.end());
				string MA = string(str2.begin(), str2.end());
				string IP = string(str3.begin(), str3.end());
				//	Check if the string aren't empty
				if (FD.empty() == TRUE)
				{
					MessageBoxA(hwnd, "The friendly devices edit-text is empty!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
					break;
				}
				if (MA.empty() == TRUE)
				{
					MessageBoxA(hwnd, "The MAC Address edit-text is empty!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
					break;
				}
				if (IP.empty() == TRUE)
				{
					MessageBoxA(hwnd, "The IP Address edit-text is empty!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
					break;
				}

				//	Ask confirmation
				int ID = MessageBoxA(NULL, "Are you sure to add this device to the list of friendly devices?", "IPS: Warning", MB_YESNO | MB_ICONWARNING);
				switch (ID)
				{
				case IDYES:
					break;
				case IDNO:
					return DefWindowProc(hwnd, msg, wParam, lParam);
				case IDCANCEL:
					return DefWindowProc(hwnd, msg, wParam, lParam);
				default:
					return DefWindowProc(hwnd, msg, wParam, lParam);
				}	

				//	Add strings to list of friendly devices
				AddToFriendlyDevices(FD, MA, IP);
				LoopFileIndex(hwnd);

				ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices.ips", ios::beg);
				ofstream outfile("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices2.ips", ios::beg);
				if (!infile || !outfile)
				{
					MessageBoxA(NULL, "Failed to open Unknown-Devices.ip file!", "IPS: Error", MB_ICONERROR);
				}
				
				//	Update our listbox
				string line;
				BOOL DELETED = FALSE;
				while (getline(infile, line))
				{
					if (line.find(IP) == string::npos)
					{
						outfile << line << endl;
					}
					else
					{
						DELETED = TRUE;
					}
				}
				infile.close();
				outfile.close();
				if (DELETED == TRUE)
				{
					MessageBoxA(hwnd, "Device deleted from listbox.\n(If not wait a few seconds)", "IPS: Warning", MB_OK | MB_ICONWARNING);
				}

				//	Deleting .ips tempory file
				String^ SOURCE = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices2.ips");
				String^ DEST = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices.ips");
				File::Copy(SOURCE, DEST, TRUE);
				File::Delete(SOURCE);
				
				//	Clear textboxes
				SetSTATICText(EDIT_IPADDR, "", hwnd);
				SetSTATICText(EDIT_FRIENDLYNAME, "", hwnd);
				SetSTATICText(EDIT_MACADDR, "", hwnd);

				if (MainWindow::firewall.IsIPBlocked(IP) == TRUE)
				{
					if (MainWindow::firewall.DeleteFromBlockList(IP) == FALSE)
					{
						MessageBoxA(hwnd, "Failed to delete IP from blocked list!", "IPS: Error", MB_OK | MB_ICONERROR);
					}
				}
				break;
			}
			default:
				break;
			}
			break;
		case BTN_DELFRIENDLYDEV:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				TCHAR buff[MAX_PATH];
				HWND SelectedItem = GetDlgItem(hwnd, SELECTED_DEV);
				GetWindowText(SelectedItem, buff, MAX_PATH);
				wstring str = buff;
				string SelectedDevice = string(str.begin(), str.end());
				//	Check if the string isn't empty or if the user hasn't chosen a device
				if (SelectedDevice.empty() == TRUE || SelectedDevice == "NONE_SELECTED")
				{
					MessageBoxA(NULL, "No device selected!", "IPS: Warning", MB_OK | MB_ICONWARNING);
					break;
				}
				//	Ask confirmation
				int ID = MessageBoxA(NULL, "Are you sure to delete this device from the friendly list?", "IPS: Warning", MB_YESNO | MB_ICONWARNING);
				switch (ID)
				{
				case IDYES:
					break;
				case IDNO:
					return DefWindowProc(hwnd, msg, wParam, lParam);
				case IDCANCEL:
					return DefWindowProc(hwnd, msg, wParam, lParam);
				default:
					return DefWindowProc(hwnd, msg, wParam, lParam);
				}	

				//	Remove device.
				RemoveFromList(SelectedDevice);
				SetSTATICText(SELECTED_DEV, "NONE_SELECTED", hwnd);
				LoopFileIndex(hwnd);

				int END = SelectedDevice.find_last_of(" - ");
				string SIN = SelectedDevice.substr(20, END);
				int ENDSIN = SIN.find(" - ");
				string IP_ADDR = SIN.substr(0, ENDSIN);
				string MAC_ADDR = SelectedDevice.substr(0, 17);
				
				//	Update Online-Devices listbox
				ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::beg);
				ofstream outfile("C:\\Program Files\\IPS\\NetworkData\\Online-Devices2.ips", ios::beg);
				if (!infile || !outfile)
				{
					MessageBoxA(hwnd, "Failed to open Online-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
					break;
				}

				string line;
				BOOL DELETED = FALSE;
				while (getline(infile, line))
				{
					if (line.find(MAC_ADDR) == string::npos)
					{
						outfile << line << endl;
					}
					else
					{
						DELETED = TRUE;
					}
				}
				infile.close();
				outfile.close();

				if (DELETED == FALSE)
				{
					MessageBoxA(hwnd, "Failed to delete device from Online-Devices list!", "IPS: Error", MB_OK | MB_ICONERROR);
				}
				else
				{
					MessageBoxA(hwnd, "Device succesfully deleted from listbox!", "IPS: Warning", MB_OK | MB_ICONWARNING);
				}

				//	Deleting .ips tempory file
				String^ SOURCE = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Online-Devices2.ips");
				String^ DEST = gcnew String("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips");
				File::Copy(SOURCE, DEST, TRUE);
				File::Delete(SOURCE);

				if (MainWindow::firewall.IsIPBlocked(IP_ADDR) == TRUE)
				{
					if (MainWindow::firewall.AddNewToBlockList(IP_ADDR) == FALSE)
					{
						MessageBoxA(hwnd, "Failed to add IP to blocked list!", "IPS: Error", MB_OK | MB_ICONERROR);
					}
				}
				break;
			}
			default:
				break;
			}
			break;
		default:
			break;
		}
		break;
	}
	case WM_CLOSE:
	{
		if (ActionWindow::WindowOpen == TRUE || ActionWindow2::WindowOpen == TRUE)
		{
			MessageBoxA(hwnd, "ActionWindow still open!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
			break;
		}
		CloseWindow(hwnd);
		DestroyWindow(hwnd);
		break;
	}
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
	return 0;
}

void *NetworkCTRLDialog::LoopingOnlineDevices(HWND hwnd)
{
	while (true)
	{
		SendMessage(GetDlgItem(hwnd, LISTBOX_ONLINEDEV), LB_RESETCONTENT, 0, 0);

		ifstream openfile("C:\\Program Files\\IPS\\NetworkData\\Online-Devices.ips", ios::beg);
		if (!openfile)
		{
			MessageBoxA(NULL, "Failed to open Online-Devices file!", "IPS: Error", MB_OK | MB_ICONERROR);
			return 0;
		}
		string line;
		while (getline(openfile, line))
		{
			SendMessageA(GetDlgItem(hwnd, LISTBOX_ONLINEDEV), LB_ADDSTRING, 0, (LPARAM)line.c_str());
		}
		openfile.close();
		Sleep(3000);
	}
	return 0;
}
void *NetworkCTRLDialog::LoopingUnknownDevices(HWND hwnd)
{
	while (true)
	{
		SendMessage(GetDlgItem(hwnd, LISTBOX_UNKNOWNDEV), LB_RESETCONTENT, 0, 0);
		ifstream openfile("C:\\Program Files\\IPS\\NetworkData\\Unknown-Devices.ips", ios::beg);
		if (!openfile)
		{
			MessageBoxA(NULL, "Failed to open Unknown-Devices file!", "IPS: Error", MB_OK | MB_ICONERROR);
			return 0;
		}
		string line;
		while (getline(openfile, line))
		{
			int END = line.find_last_of(" - ");
			string SIN = line.substr(20, END);
			int ENDSIN = SIN.find(" - ");
			string IP_ADDR = SIN.substr(0, ENDSIN);
			if (MainWindow::firewall.IsIPBlocked(IP_ADDR) == FALSE)
			{
				if (FALSE == MainWindow::firewall.AddNewToBlockList(IP_ADDR))
				{
					MessageBoxA(hwnd, "Failed to add IP to blocked list!", "IPS: Error", MB_OK | MB_ICONERROR);
				}
			}
			SendMessageA(GetDlgItem(hwnd, LISTBOX_UNKNOWNDEV), LB_ADDSTRING, 0, (LPARAM)line.c_str());
		}
		openfile.close();
		Sleep(3000);
	}
	return 0;
}
void NetworkCTRLDialog::LoopFileIndex(HWND hwnd)
{
	HWND ListBox = GetDlgItem(hwnd, LISTBOX_FILE);
	SendMessage(ListBox, LB_RESETCONTENT, 0, 0);
	ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Friendly-Devices.ips", ios::beg);
	if (!infile)
	{
		MessageBoxA(hwnd, "Failed to open Friendly-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
		return;
	}
	string firstline;
	string secondline;
	string line;
	BOOL FIRSTL = FALSE;
	while (getline(infile, line))
	{
		if (FIRSTL == FALSE)
		{
			firstline = line;
			FIRSTL = TRUE;
		}
		else
		{
			secondline = line;
			string msg = firstline + " " + secondline;
			SendMessageA(ListBox, LB_ADDSTRING, 0, (LPARAM)msg.c_str());
			//MessageBoxA(hwnd, msg.c_str(), "IPS: Info", MB_OK);
			FIRSTL = FALSE;
		}
	}
}
void NetworkCTRLDialog::AddToFriendlyDevices(string FriendlyName, string MACAddr, string IpAddr)
{
	//	First check if the values are correct.
	unsigned long IP = inet_addr(IpAddr.c_str());
	if (IP == INADDR_NONE)
	{
		MessageBoxA(NULL, "Invalid IP Address given!", "IPS: Warning", MB_OK | MB_ICONWARNING);
		return;
	}
	if (MACAddr.length() != 17)
	{
		MessageBoxA(NULL, "Invalid MAC address given!", "IPS: Warning", MB_OK | MB_ICONWARNING);
		return;
	}
	ofstream outfile("C:\\Program Files\\IPS\\NetworkData\\Friendly-Devices.ips", ios::app);
	if (!outfile)
	{
		MessageBoxA(NULL, "Failed to open Friendly-Device.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
			return;
	}
	outfile << MACAddr << " _ " << IpAddr << endl;
	outfile << FriendlyName << endl;
	outfile.close();
	MessageBoxA(NULL, "Friendly device added to list", "IPS: Info", MB_OK | MB_ICONINFORMATION);
}
void NetworkCTRLDialog::SetSTATICText(int ID, string text, HWND hwnd)
{
	SetWindowTextA(GetDlgItem(hwnd, ID), text.c_str());
	ShowWindow(GetDlgItem(hwnd, ID), SW_HIDE);
	ShowWindow(GetDlgItem(hwnd, ID), SW_SHOW);
}
void NetworkCTRLDialog::RemoveFromList(string item)
{
	ifstream checker("C:\\Program Files\\IPS\\NetworkData\\Friendly-Devices.ips", ios::beg);
	ofstream adder("C:\\Program Files\\IPS\\NetworkData\\Friendly-Devices2.ips", ios::trunc);
	if (!checker)
	{
		MessageBoxA(NULL, "Failed to open Friendly-Devices.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
		return;
	}
	else if (!adder)
	{
		MessageBoxA(NULL, "Failed to create Friendly-Devices2.ips file!", "IPS: Error", MB_OK | MB_ICONERROR);
		return;
	}
	string line;
	string MAC_ADDR = item.substr(0, 17);

	BOOL LINE_FOUND = FALSE;
	while (getline(checker, line))
	{
		//	If the string is not found.
		if (line.find(MAC_ADDR) == string::npos)
		{
			LINE_FOUND = TRUE;
			adder << line << endl;
			getline(checker, line);
			adder << line << endl;
		}
		//	If the string is found.
		else
			getline(checker, line);
	}
	checker.close();
	adder.close();
	System::String^ dst = gcnew System::String("C:\\Program Files\\IPS\\NetworkData\\Friendly-Devices.ips");
	System::String^ src = gcnew System::String("C:\\Program Files\\IPS\\NetworkData\\Friendly-Devices2.ips");
	File::Copy(src, dst, TRUE);
	File::Delete(src);

	if (LINE_FOUND == TRUE)
		MessageBoxA(NULL, "Device deleted succesfully!", "IPS: Info", MB_OK | MB_ICONINFORMATION);
	else
		MessageBoxA(NULL, "Device failed to delete!", "IPS: Warning", MB_OK | MB_ICONERROR);
}

//	CustomFirewallDialog Function
BOOL CustomFirewallDialog::RegisterDialog(HINSTANCE hInstance)
{
	WNDCLASSEX wc;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = 0;
	wc.lpfnWndProc = CustomFirewallDialog::DialogProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadIcon(NULL, IDC_HAND);
	wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
	wc.lpszMenuName = L"TITLE";
	wc.lpszClassName = L"CustomFirewallDialog";
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	return RegisterClassEx(&wc);
}
BOOL CustomFirewallDialog::StartDialog(HINSTANCE hInstance, HWND HwndParent)
{
	HWND hwnd = CreateWindowEx(WS_POPUP, L"CustomFirewallDialog", L"Custom Firewall Dialog",
		WS_MINIMIZEBOX | WS_SYSMENU |WS_CAPTION | WS_OVERLAPPED, CW_USEDEFAULT, CW_USEDEFAULT, 600, 350, HwndParent,
		NULL, hInstance, NULL);
	if (hwnd == NULL)
	{
		MessageBoxA(NULL, "Failed to create a window!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
		return FALSE;
	}
	CustomFirewallDialog::HwndDialog = hwnd;
	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);
	return TRUE;
}
void CustomFirewallDialog::InitializeDialog(HWND HwndParent)         
{
	HWND hwndLabel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Custom Firewall"), SS_LEFT | WS_VISIBLE | WS_CHILD | WS_SYSMENU,
		10, 10, 300, 25,
		HwndParent, (HMENU)LABEL_TEXT,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND StatusL = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Status:"), SS_LEFT | WS_VISIBLE | WS_CHILD | WS_SYSMENU,
		10, 30, 300, 25,
		HwndParent, (HMENU)STATUS_LABEL2,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND StatusL2 = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Unknown"),
		SS_LEFT | WS_VISIBLE | WS_CHILD | WS_SYSMENU,
		150, 30, 300, 25,
		HwndParent, (HMENU)STATUS_LABEL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND OnOffBtn = CreateWindow(L"BUTTON", L"Stop Firewall", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		400, 30, 150, 30,
		HwndParent, (HMENU)ONOFF_BTN,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND ListBoxLabel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Blocked IP-Addresses:"), SS_LEFT | WS_VISIBLE | WS_CHILD | WS_SYSMENU | WS_BORDER,
		10, 50, 300, 25,
		HwndParent, (HMENU)LABELBLOCKEDIP,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND HwndListBox = CreateWindow(TEXT("listbox"), NULL, WS_CHILD | WS_VISIBLE | LBS_STANDARD,
		10, 80, 300, 200,
		HwndParent, (HMENU)BLOCKEDIP_LISTBOX,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND SelectedLabel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Rule to delete:"), SS_LEFT | WS_VISIBLE | WS_CHILD | WS_SYSMENU,
		325, 90, 300, 25,
		HwndParent, (HMENU)RULE_LABEL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND RuleToDel = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("NONE_SELECTED"), SS_LEFT | WS_VISIBLE | WS_CHILD | WS_SYSMENU,
		350, 110, 300, 25,
		HwndParent, (HMENU)RULETODELETE_LABEL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND DelRuleBtn = CreateWindow(L"BUTTON", L"Delete Rule", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		400, 130, 150, 30,
		HwndParent, (HMENU)DELETERULE_BTN,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);


	HWND LABELADD = CreateWindowEx(WS_EX_TRANSPARENT, L"STATIC", TEXT("Rule to add:"), SS_LEFT | WS_VISIBLE | WS_CHILD | WS_SYSMENU,
		325, 170, 300, 25,
		HwndParent, (HMENU)ADDRULE_LABEL,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

	HWND IPTextBox = CreateWindow(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL | ES_WANTRETURN,
		350, 190, 200, 25,
		HwndParent, (HMENU)IPADDR_TEXTBOX,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);
	
	HWND AddRuleBtn = CreateWindow(L"BUTTON", L"Add Rule", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		400, 220, 150, 30,
		HwndParent, (HMENU)ADDRULE_BTN,
		(HINSTANCE)GetWindowLong(HwndParent, GWL_HINSTANCE), NULL);

}
void CustomFirewallDialog::SetIcon(HWND HwndMain)
{
	HICON IconSmall = NULL;
	HICON IconBig = NULL;

	if ((IconSmall = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconSmall = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 16, 16, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load small icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	if ((IconBig = (HICON)LoadImageA(NULL, "C:\\Program Files\\IPS\\Images\\IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
	{
		if ((IconBig = (HICON)LoadImageA(NULL, "IPS-Icon.ico", IMAGE_ICON, 32, 32, LR_LOADFROMFILE)) == NULL)
		{
			MessageBoxA(NULL, "Failed to load big icon!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	SendMessage(HwndMain, WM_SETICON, ICON_SMALL, (LPARAM)IconSmall);
	SendMessage(HwndMain, WM_SETICON, ICON_BIG, (LPARAM)IconBig);
}
void *CustomFirewallDialog::ShowDialog(HWND hwnd, HINSTANCE hInstance)
{
	if (RegisterDialog(hInstance) == FALSE)
	{
		MessageBoxA(hwnd, "Failed Register Dialog!", "IPS: Error", MB_OK | MB_ICONERROR);
		stringstream ss;
		ss << "Error code: " << GetLastError();
		string str = ss.str();
		MessageBoxA(hwnd, str.c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}
	if (StartDialog(hInstance, hwnd) == FALSE)
	{
		MessageBoxA(hwnd, "Failed to start dialog!", "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}
	CustomFirewallDialog::DialogShown = TRUE;
	MSG msg;
	while (GetMessage(&msg, 0, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	CloseDialog();
	return 0;
}
void CustomFirewallDialog::CloseDialog()
{
	CustomFirewallDialog::DialogShown = FALSE;
	UnregisterClass(L"CustomFirewallDialog", (HINSTANCE)GetModuleHandle(L"CustomFirewallDialog"));
	TerminateThread(CustomFirewallDialog::DialogHandle, 0);
}
void CustomFirewallDialog::SetSTATICText(int ID, string text, HWND hwnd)
{
	SetWindowTextA(GetDlgItem(hwnd, ID), text.c_str());
	ShowWindow(GetDlgItem(hwnd, ID), SW_HIDE);
	ShowWindow(GetDlgItem(hwnd, ID), SW_SHOW);
}
LRESULT CALLBACK CustomFirewallDialog::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CREATE:
	{
		InitializeDialog(hwnd);
		SetIcon(hwnd);
		if (MainWindow::firewall.FWisRunning() == TRUE)
		{
			SetWindowTextA(GetDlgItem(hwnd, STATUS_LABEL), "Online");
			SendMessageA(GetDlgItem(hwnd, STATUS_LABEL), WM_SETTEXT, 0, (LPARAM)"Online");
		}
		else
		{
			SetWindowTextA(GetDlgItem(hwnd, STATUS_LABEL), "Offline");
			SendMessageA(GetDlgItem(hwnd, STATUS_LABEL), WM_SETTEXT, 0, (LPARAM)"Offline");
			SetWindowTextA(GetDlgItem(hwnd, ONOFF_BTN), "Start Firewall");
			SendMessageA(GetDlgItem(hwnd, ONOFF_BTN), WM_SETTEXT, 0, (LPARAM)"Start Firewall");
		}
		ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips", ios::beg);
		if (!infile)
		{
			MessageBoxA(NULL, "Failed to open file: ""Blocked-List.ips""", "IPS: Error", MB_OK | MB_ICONERROR);
		}
		else
		{
			string line;
			while (getline(infile, line))
			{
				HWND ListBox = GetDlgItem(hwnd, BLOCKEDIP_LISTBOX);
				SendMessageA(ListBox, LB_ADDSTRING, (WPARAM)NULL, (LPARAM)line.c_str());
			}
			infile.close();
		}
		break;
	}
	case WM_CTLCOLORSTATIC:
	{
		HDC hdcStatic = (HDC)wParam;
		SetTextColor(hdcStatic, RGB(255, 255, 255));
		SetBkMode(hdcStatic, TRANSPARENT);
		return (LRESULT)GetStockObject(NULL_BRUSH);
	}
	case WM_COMMAND:
	{
		//	Window control events.
		switch (LOWORD(wParam))
		{
		//	Firewall on/off button
		case ONOFF_BTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				if (MainWindow::firewall.FWisRunning() == TRUE)
				{
					//	Stop Firewall
					if (MainWindow::firewall.StopFirewall() == TRUE)
					{
						MessageBoxA(hwnd, "Firewall stopped!", "IPS: Info", MB_OK | MB_ICONEXCLAMATION);

						SetSTATICText(ONOFF_BTN, "Start Firewall", hwnd);
						SetSTATICText(STATUS_LABEL, "Offline", hwnd);
					}
					else
					{
						MessageBoxA(hwnd, "Failed to stop firewall!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
					}
				}
				else
				{
					//	Start Firewall
					if (MainWindow::firewall.StartFirewall() == TRUE)
					{
						MessageBoxA(hwnd, "Firewall started!", "IPS: Info", MB_OK | MB_ICONEXCLAMATION);

						SetSTATICText(ONOFF_BTN, "Stop Firewall", hwnd);
						SetSTATICText(STATUS_LABEL, "Online", hwnd);
					}
					else
					{
						MessageBoxA(hwnd, "Failed to start firewall!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
					}
				}
				break;
			}
			default:
				break;
			}
			break;
		//	Listbox events
		case BLOCKEDIP_LISTBOX:
			switch (HIWORD(wParam))
			{
			case LBN_SELCHANGE:
			{
				int SelectedItem = (int)SendMessage(GetDlgItem(hwnd, BLOCKEDIP_LISTBOX), LB_GETCURSEL, 0, 0);
				TCHAR buff[MAX_PATH];
				SendMessage(GetDlgItem(hwnd, BLOCKEDIP_LISTBOX), LB_GETTEXT, SelectedItem, (LPARAM)buff);
				wstring str = buff;
				string SelItem = string(str.begin(), str.end());
				SetSTATICText(RULETODELETE_LABEL, SelItem, hwnd);
				break;
			}
			default:
				break;
			}
			break;
		//	Delete rule button
		case DELETERULE_BTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				TCHAR buff[MAX_PATH];
				GetWindowText(GetDlgItem(hwnd, RULETODELETE_LABEL), buff, MAX_PATH);
				wstring str = buff;
				string IpToDelete = string(str.begin(), str.end());
				if (IpToDelete.find("NONE_") != string::npos)
				{
					MessageBoxA(hwnd, "First select a rule!", "IPS: Warning", MB_OK | MB_ICONEXCLAMATION);
					break;
				}
				int ID = MessageBoxA(hwnd, "Are you sure to delete the rule!?", "IPS: Warning", MB_ICONQUESTION | MB_YESNOCANCEL);
				//	User's choise
				switch (ID)
				{
				case IDYES:
				{
					MainWindow::firewall.DeleteFromBlockList(IpToDelete);
					break;
				}
				case IDNO:
					break;
				case IDCANCEL:
					break;
				default:
					break;
				}
				//	Update listbox
				SendMessage(GetDlgItem(hwnd, BLOCKEDIP_LISTBOX), LB_RESETCONTENT, 0, 0);
				ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips", ios::beg);
				if (!infile)
				{
					MessageBoxA(NULL, "Failed to open file: ""Blocked-List.ips""", "IPS: Error", MB_OK | MB_ICONERROR);
				}
				else
				{
					string line;
					while (getline(infile, line))
					{
						HWND ListBox = GetDlgItem(hwnd, BLOCKEDIP_LISTBOX);
						SendMessageA(ListBox, LB_ADDSTRING, (WPARAM)NULL, (LPARAM)line.c_str());
					}
					infile.close();
				}
				//	Update label
				SetSTATICText(RULETODELETE_LABEL, "NONE_SELECTED", hwnd);
				break;
			}
			default:
				break;
			}
			break;
		//	Add rule button
		case ADDRULE_BTN:
			switch (HIWORD(wParam))
			{
			case BN_CLICKED:
			{
				TCHAR buff[MAX_PATH];
				GetWindowText(GetDlgItem(hwnd, IPADDR_TEXTBOX), buff, MAX_PATH);
				wstring str = buff;
				string IPADDR = string(str.begin(), str.end());
				//	Check if textbox string is empty or not
				if (IPADDR == "" || IPADDR.empty() == TRUE)
				{
					MessageBoxA(hwnd, "No IP Address given to add!", "IPS: Warning", MB_OK | MB_ICONWARNING);
					SetSTATICText(IPADDR_TEXTBOX, "", hwnd);
					break;
				}
				//	Check if string is really a IP Address
				unsigned long ulAddr = inet_addr(IPADDR.c_str());
				if (ulAddr == INADDR_NONE || ulAddr == INADDR_ANY)
				{
					MessageBoxA(hwnd, "The given value is not a IP Address!", "IPS: Warning", MB_OK | MB_ICONWARNING);
					SetSTATICText(IPADDR_TEXTBOX, "", hwnd);
					break;
				}
				//	Users choise.
				int ID = MessageBoxA(hwnd, "Are you sure to add this IP Address to the list?", "IPS: Info", MB_YESNOCANCEL | MB_ICONQUESTION);
				switch (ID)
				{
				case IDYES:
					if (TRUE == MainWindow::firewall.AddNewToBlockList(IPADDR))
						MessageBoxA(hwnd, "Succesfully added IP to blocked list!", "IPS: Info", MB_OK | MB_ICONWARNING);
					else
						MessageBoxA(hwnd, "Failed to add IP to blocked list!", "IPS: Error", MB_OK | MB_ICONERROR);
					break;
				case IDNO:
					break;
				case IDCANCEL:
					break;
				}

				//	Update listbox
				SendMessage(GetDlgItem(hwnd, BLOCKEDIP_LISTBOX), LB_RESETCONTENT, 0, 0);
				ifstream infile("C:\\Program Files\\IPS\\NetworkData\\Blocked-List.ips", ios::beg);
				if (!infile)
				{
					MessageBoxA(NULL, "Failed to open file: ""Blocked-List.ips""", "IPS: Error", MB_OK | MB_ICONERROR);
				}
				else
				{
					string line;
					while (getline(infile, line))
					{
						HWND ListBox = GetDlgItem(hwnd, BLOCKEDIP_LISTBOX);
						SendMessageA(ListBox, LB_ADDSTRING, (WPARAM)NULL, (LPARAM)line.c_str());
					}
					infile.close();
				}
				//	Clear textbox
				SetSTATICText(IPADDR_TEXTBOX, "", hwnd);
				break;
			}
			default:
				break;
			}
			break;
		//	Default action
		default:
			break;
		}
		break;
	}
	case WM_DESTROY:
	{
		PostQuitMessage(0);
		break;
	}
	case WM_CLOSE:
	{
		DestroyWindow(hwnd);
		break;
	}
	default:
		return DefWindowProc(hwnd, msg, wParam, lParam);
	}
}

//	Networking and Internet
//	https://msdn.microsoft.com/en-us/library/windows/desktop/ee663286(v=vs.85).aspx

//	USE Windows filtering for blocking IP addresses 
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa364943(v=vs.85).aspx

//	USE CreatePersistentTcpPortReservation() 
//	for blocking incoming tcp port connections
//	https://msdn.microsoft.com/en-us/library/windows/desktop/gg696068(v=vs.85).aspx

//	WIFI programming
//	https://msdn.microsoft.com/en-us/library/windows/desktop/ms706275(v=vs.85).aspx