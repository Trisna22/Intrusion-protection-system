#pragma once
#include <Windows.h>
#include <iostream>
#include <sstream>

#pragma comment(lib, "Winmm.lib")

using namespace std;

#ifndef Notification_H
#define Notification_H

class Notification
{
public:
	Notification(TCHAR*);
	
	void StartNotification();
	void StartNotification(string);

	void ShowNotificationNoThread();
	void ShowNotificationNoThread(string);
	
	static DWORD WINAPI ShowNotification(LPVOID);
	static DWORD WINAPI ShowNotification2(LPVOID);
private:
	static DWORD WINAPI MakeSound1(LPVOID);

	BOOL RegisterNotification(HINSTANCE);
	static BOOL RegisterNotification2(HINSTANCE, TCHAR*);
	
	BOOL CreateNotification(HINSTANCE, HWND);
	static BOOL CreateNotification2(HINSTANCE, HWND, TCHAR*);
	
	static int InitializeDialog(HWND);
	static int InitializeDialog(HWND, string);
	static int SetIcon(HWND);
	
	static BOOL LoadAndBlitBitmap(LPCWSTR, HDC);
	static LRESULT CALLBACK WindowProc(HWND, UINT, WPARAM, LPARAM);
	static void WindowCleanup();
	static void WindowCleanup(TCHAR* className);
private:	//	Important Variables
	HWND HwndMain;
	HANDLE NotifyHandler = NULL;
	HANDLE Slumber = NULL;
	DWORD NotifyID = 0;
	struct ThreadParams
	{
		string NotificationMsg;
		TCHAR* ClassName;
		int LuckyNumber;
	};
	TCHAR* ClassName_ = L"NO_CLASS";
	BOOL OwnClass = FALSE;
};
#endif // !Notification_H

Notification::Notification(TCHAR* className)
{
	ClassName_ = className;
	OwnClass = TRUE;
}

void Notification::StartNotification()
{
	//	IF "NotifyHandler" thread is running kill it and restart it again
	DWORD dwThread = WaitForSingleObject(NotifyHandler, 0);
	if (dwThread == WAIT_TIMEOUT)
	{
		MessageBoxA(NULL, "Thread is still running", "IPS: Info", MB_OK);
		return;
	}
	CreateThread(NULL, 0, &MakeSound1, (void*)NULL, NULL, NULL);
	NotifyHandler = CreateThread(NULL, 0, &ShowNotification, (LPVOID)NULL, NULL, NULL);
	if (!NotifyHandler)
	{
		MessageBoxA(NULL, "Failed to start thread!", "IPS: Info", MB_OK);
	}
}
void Notification::StartNotification(string msg)
{
	//	IF "NotifyHandler" thread is running kill it and restart it again
	DWORD dwThread = WaitForSingleObject(NotifyHandler, 1000);
	if (dwThread == WAIT_TIMEOUT)
	{
		//	Kill the thread, bc its running.
		if (PostMessage(FindWindowEx(NULL, NULL, ClassName_, NULL), WM_CLOSE, 0, 0) == FALSE)
		{
			stringstream ss;
			ss << "Failed to CloseWindow(hwnd) error code: " << GetLastError() << endl;
			MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK);
		}
		if (TerminateThread(NotifyHandler, 0) == FALSE)
		{
			MessageBoxA(NULL, "Failed to kill thread!!", "IPS: Error", MB_OK | MB_ICONERROR);
		}
	}
	CreateThread(NULL, 0, &MakeSound1, (void*)NULL, NULL, NULL);
	//	Create parameters struct to pass in thread function
	ThreadParams *params = new ThreadParams();
	params->NotificationMsg = msg;
	params->LuckyNumber = 22;
	params->ClassName = ClassName_;
	NotifyHandler = CreateThread(NULL, 0, &ShowNotification2, (LPVOID)params, NULL, NULL);
	if (!NotifyHandler)
	{
		MessageBoxA(NULL, "Failed to start thread!", "IPS: Info", MB_OK);
	}
}

DWORD WINAPI Notification::ShowNotification(LPVOID param)
{
	//	Notification with creating a thread

	if (!RegisterNotification2((HINSTANCE)GetWindowLong(GetDesktopWindow(), GWL_HINSTANCE), L"NotificationWindow"))
	{
		MessageBoxA(NULL, "Failed to Register Notification class!!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
		return 0;
	}
	if (!CreateNotification2((HINSTANCE)GetWindowLong(GetDesktopWindow(), GWL_HINSTANCE), GetDesktopWindow(), L"NotificationWindow"))
	{
		MessageBoxA(NULL, "Failed to show notification window!!!", "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	WindowCleanup();
}
DWORD WINAPI Notification::ShowNotification2(LPVOID param)
{
	//	Notification with creating a thread
	string message = ((ThreadParams*)param)->NotificationMsg;
	TCHAR* className = ((ThreadParams*)param)->ClassName;

	if (!RegisterNotification2((HINSTANCE)GetWindowLong(GetDesktopWindow(), GWL_HINSTANCE),className))
	{
		WindowCleanup(className);
		if (!RegisterNotification2((HINSTANCE)GetWindowLong(GetDesktopWindow(), GWL_HINSTANCE), className))
		{
			MessageBoxA(NULL, "Failed to Register Notification class!!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
			return 0;
		}
	}
	if (!CreateNotification2((HINSTANCE)GetWindowLong(GetDesktopWindow(), GWL_HINSTANCE), GetDesktopWindow(), className))
	{
		MessageBoxA(NULL, "Failed to show notification window!!!", "IPS: Error", MB_OK | MB_ICONERROR);
		return 0;
	}
	//	Check if we have a msg or not
	if (message != "" || message.empty() == FALSE)
		InitializeDialog(FindWindowEx(NULL, NULL, className, NULL), message);
	else
		InitializeDialog(FindWindowEx(NULL, NULL, className, NULL));

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	WindowCleanup(className);
}

void Notification::ShowNotificationNoThread()
{
	//	Notification without creating a thread and no msg
}
void Notification::ShowNotificationNoThread(string msg)
{
	//	Notification without creating a thread and a msg
}

DWORD WINAPI Notification::MakeSound1(LPVOID)
{
	if (PlaySoundA("C:\\Program Files\\IPS\\Sounds\\IPS-Notify.wav", NULL, SND_FILENAME) == FALSE)
	{
		MessageBoxA(NULL, "Failed to start sound 1!", "IPS: Error", MB_OK | MB_ICONEXCLAMATION);
	}
	return 0;
}

BOOL Notification::RegisterNotification(HINSTANCE hInstance)
{
	WNDCLASSEX wc;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = WS_EX_TOPMOST;
	wc.lpfnWndProc = Notification::WindowProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadIcon(NULL, IDC_HAND);
	wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
	wc.lpszMenuName = L"TITLE";
	wc.lpszClassName = L"NotificationWindow";
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	return RegisterClassEx(&wc);
}
BOOL Notification::RegisterNotification2(HINSTANCE hInstance, TCHAR* className)
{
	WNDCLASSEX wc;
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = WS_EX_TOPMOST;
	wc.lpfnWndProc = Notification::WindowProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc.hCursor = LoadIcon(NULL, IDC_HAND);
	wc.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
	wc.lpszMenuName = L"TITLE";
	wc.lpszClassName = className;
	wc.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
	return RegisterClassEx(&wc);
}

BOOL Notification::CreateNotification(HINSTANCE hInstance, HWND hwndParent)
{
	//	Get resolution of screen
	RECT desktop;
	GetWindowRect(GetDesktopWindow(), &desktop);
	int XPos = desktop.right - 400;
	int YPos = desktop.bottom - 250;
	HWND hwnd = CreateWindowEx(WS_EX_CLIENTEDGE | WS_EX_TOPMOST, L"NotificationWindow", L"IPS: Notification.", WS_SYSMENU | WS_CAPTION | SWP_NOSIZE | SWP_NOMOVE | WS_EX_TOPMOST, XPos, YPos, 400, 250, NULL, NULL, hInstance, NULL);
	if (hwnd == NULL)
	{
		MessageBoxA(NULL, "Failed to create nofitication!!", "IPS: Error", MB_OK | MB_ICONASTERISK);
		return FALSE;
	}
	HwndMain = hwnd;
	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);
	return TRUE;
}
BOOL Notification::CreateNotification2(HINSTANCE hInstance, HWND hwndParent, TCHAR* className)
{
	//	Get resolution of screen
	RECT desktop;
	GetWindowRect(GetDesktopWindow(), &desktop);
	int XPos = desktop.right - 400;
	int YPos = desktop.bottom - 250;
	HWND hwnd = CreateWindowEx(WS_EX_CLIENTEDGE | WS_EX_TOPMOST, 
		className, L"IPS: Notification.",
		WS_SYSMENU | WS_CAPTION | SWP_NOSIZE | SWP_NOMOVE | WS_EX_TOPMOST, 
		XPos, YPos, 400, 250, NULL, NULL, hInstance, NULL);
	if (hwnd == NULL)
	{
		MessageBoxA(NULL, "Failed to create nofitication!!", "IPS: Error", MB_OK | MB_ICONASTERISK);
		return FALSE;
	}
	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);
	return TRUE;
}

int Notification::InitializeDialog(HWND hwnd)
{
	HWND Label = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", "No Message", WS_CHILD | WS_VISIBLE | WS_SYSMENU,
		10, 10, 500, 50,
		hwnd, (HMENU)L"Label",
		(HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE), NULL);
	return 0;
}
int Notification::InitializeDialog(HWND hwnd, string msg)
{
	HWND Label = CreateWindowExA(WS_EX_TRANSPARENT, "STATIC", msg.c_str(), WS_CHILD | WS_VISIBLE | WS_SYSMENU,
		10, 10, 500, 50, 
		hwnd, (HMENU)L"Label",
		(HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE), NULL);
	return 0;
}
int Notification::SetIcon(HWND hwnd)
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
	return 0;
}

BOOL Notification::LoadAndBlitBitmap(LPCWSTR szFilename, HDC hWinDC)
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
	BOOL qRetBlit = BitBlt(hWinDC, 140, 40, qBitmap.bmWidth, qBitmap.bmHeight,
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
LRESULT CALLBACK Notification::WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg)
	{
	case WM_CREATE:
	{
		SetIcon(hwnd);
		break;
	}
	case WM_CTLCOLORSTATIC:
	{
		HDC hdcStatic = (HDC)wParam;
		SetTextColor(hdcStatic, RGB(255, 255, 255));
		SetBkMode(hdcStatic, TRANSPARENT);
		return (LRESULT)GetStockObject(NULL_BRUSH);
	}
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hwnd, &ps);

		if (LoadAndBlitBitmap(TEXT("C:\\Program Files\\IPS\\Images\\IPS-Devices.bmp"), hdc) == FALSE)
		{
			if (LoadAndBlitBitmap(TEXT("IPS-Devices.bmp"), hdc) == FALSE)
			{
				MessageBoxA(hwnd, "Loading Image Failed!", "IPS: Error", MB_OK | MB_ICONERROR);
			}
		}
		EndPaint(hwnd, &ps);
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
void Notification::WindowCleanup()
{
	BOOL result = UnregisterClassA("NotificationWindow", (HINSTANCE)GetModuleHandle(L"NotificationWindow"));
	if (result == FALSE)
	{
		if (GetLastError() == 1411)
			return;
		stringstream ss;
		ss << "UnRegister class failed with error: " << GetLastError() << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
	}
}
void Notification::WindowCleanup(TCHAR* className)
{
	BOOL result = UnregisterClass(className, (HINSTANCE)GetModuleHandle(className));
	if (result == FALSE)
	{
		if (GetLastError() == 1411)
			return;
		stringstream ss;
		ss << "UnRegister class failed with error: " << GetLastError() << endl;
		MessageBoxA(NULL, ss.str().c_str(), "IPS: Error", MB_OK | MB_ICONERROR);
	}
}