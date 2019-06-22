#pragma once

#include "stdafx.h"
using namespace System::IO;
#define INFO_BUFFER_SIZE 32767

#ifndef SoftwareInstall_H
#define SoftwareInstall_H
class SoftwareInstall
{
public:
	SoftwareInstall();
	~SoftwareInstall();
	BOOL ResourceOnline();
	string ResourcePath();
	string ImageResourcePath();
	string SoundResourcePath();
	BOOL CreateResources();
private:
	string Get_Username();
	string Get_SoftwareLoc();
};
#endif // !SoftwareInstall_H

SoftwareInstall::SoftwareInstall() 
{

}
SoftwareInstall::~SoftwareInstall()
{

}
BOOL SoftwareInstall::ResourceOnline()
{
	System::String^ path = gcnew System::String(ResourcePath().c_str());
	return Directory::Exists(path);
}
string SoftwareInstall::ResourcePath()
{
	return "C:\\Program Files\\IPS";
}
string SoftwareInstall::ImageResourcePath()
{
	return "C:\\Program Files\\IPS\\Images";
}
string SoftwareInstall::SoundResourcePath()
{
	return "C:\\Program Files\\IPS\\Sounds";
}
BOOL SoftwareInstall::CreateResources()
{
	System::String^ str = gcnew System::String(ResourcePath().c_str());
	Directory::CreateDirectory(str);

	//	Software information file
	ofstream infile(ResourcePath() + "\\Software Information.txt", ios::trunc);
	if (!infile)
	{
		MessageBoxA(NULL, "Failed to create Software Information File!", "IPS: Error", MB_OK | MB_ICONERROR);
		return FALSE;
	}
	infile << "		Software Information:____\n\n";
	infile << "		* Name:				Intrusion Protection System (IPS)\n";
	infile << "		* Author:			Trisna Quebe\n";
	infile << "		* Language:			c++ win32\n";
	infile << "		* Creation Date:		23-11-2017\n";
	infile << "		* CopyRights:			(c) 2017 Trisna Quebe\n";
	infile << "		* Version:			1.4.6\n";
	infile << "		* Description:			Protects a computer/network against\n";
	infile << "							virusses and hack attacks.\n";
	infile << "		 ____     ___    _      _   _       __\n";
	infile << "		| () /   / ^ \\  | \\_/\\_/ | | | _   /  \\\n";
	infile << "		|  <    | (_) | |  ^  ^  | | () \\ ( <> )\n";
	infile << "		|_| \\_\\ |_| |_| |_||__||_| |_,__/  \\__/\n";
	infile << "		__!________________@\n";
	infile << "			$___________________________^__________________*\n";
	infile << "	           ______________________&&\n";
	infile << "		________#_______________~_________________%\n";
	infile << "		    __________________________________________\n";
	infile.close();

	string imgPath = ResourcePath() + "\\Images";
	System::String^ imgDir = gcnew System::String(imgPath.c_str());
	Directory::CreateDirectory(imgDir);
	string NetworkData = ResourcePath() + "\\NetworkData";
	System::String^ NetworkDataDir = gcnew System::String(NetworkData.c_str());
	Directory::CreateDirectory(NetworkDataDir);
	string Sounds = ResourcePath() + "\\Sounds";
	System::String^ SoundsDir = gcnew System::String(Sounds.c_str());
	Directory::CreateDirectory(SoundsDir);

	//	Network data files
	ofstream outfile(ResourcePath() + "\\NetworkData\\Friendly-Devices.ips", ios::trunc);
	outfile.close();
	ofstream outfile2(ResourcePath() + "\\NetworkData\\Online-Devices.ips", ios::trunc);
	outfile2.close();
	ofstream outfile3(ResourcePath() + "\\NetworkData\\Unknown-Devices.ips", ios::trunc);
	outfile3.close();
	ofstream outfile4(ResourcePath() + "\\NetworkData\\Blocked-List.ips", ios::trunc);
	outfile4.close();

	//	Copying resources and program to ips folder
	System::String^ source = gcnew System::String(Get_SoftwareLoc().c_str());
	string d = ResourcePath() + "\\Intrusion Protection System.exe";
	System::String^ dest = gcnew System::String(d.c_str());
	File::Copy(source, dest);

	string folder = Get_SoftwareLoc().substr(0, Get_SoftwareLoc().find_last_of("\\"));
	string image1 = folder + "\\IPS-Computer.bmp";
	string image2 = folder + "\\IPS-Firewall.bmp";
	string image3 = folder + "\\IPS-Devices.bmp";
	string image4 = folder + "\\IPS-Icon.ico";
	string sound1 = folder + "\\IPS-Notify.wav";
	System::String^ ImS = gcnew System::String(image1.c_str());
	System::String^ ImS2 = gcnew System::String(image2.c_str());
	System::String^ ImS3 = gcnew System::String(image3.c_str());
	System::String^ ImS4 = gcnew System::String(image4.c_str());
	System::String^ SoundS = gcnew System::String(sound1.c_str());
	string imaged1 = ImageResourcePath() + "\\IPS-Computer.bmp";
	string imaged2 = ImageResourcePath() + "\\IPS-Firewall.bmp";
	string imaged3 = ImageResourcePath() + "\\IPS-Devices.bmp";
	string imaged4 = ImageResourcePath() + "\\IPS-Icon.ico";
	string sounded1 = SoundResourcePath() + "\\IPS-Notify.wav";
	System::String^ ImD = gcnew System::String(imaged1.c_str());
	System::String^ ImD2 = gcnew System::String(imaged2.c_str());
	System::String^ ImD3 = gcnew System::String(imaged3.c_str());
	System::String^ ImD4 = gcnew System::String(imaged4.c_str());
	System::String^ SoundD = gcnew System::String(sounded1.c_str());
	File::Copy(ImS, ImD);
	File::Copy(ImS2, ImD2);
	File::Copy(ImS3, ImD3);
	File::Copy(ImS4, ImD4);
	File::Copy(SoundS, SoundD);
	return TRUE;
}

string SoftwareInstall::Get_Username()
{
	char username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserNameA(username, &username_len);
	return username;

}
string SoftwareInstall::Get_SoftwareLoc()
{
	char my_Path[MAX_PATH + 1];
	GetModuleFileNameA(NULL, my_Path, MAX_PATH);
	return my_Path;
}

/*


	 _______    _
	|__   __| _(_)___ _ __   __ _
	   | || '__| / __| '_ \ / _' | ________________________
	   | || |  | \__ \ | | | (_| | _____________________________
	   |_||_|  |_|___/_| |_|\__,_| ________________________
			           				 ___             _
									/ _ \ _   _  ___| |__   ___
	     ________________________  | | | | | | |/ _ \ '_ \ / _ \
	_____________________________  | |_| | |_| |  __/ |_) |  __/
		 ________________________   \__\_\\__,_|\___|_.__/ \___|






*/