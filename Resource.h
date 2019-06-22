#pragma once
#include "stdafx.h"

WCHAR MainWClassName[] = L"MainWClass";
WCHAR MainWindowTitle[] = L"Intrusion Protection System";

/****   Window Control's IDs   ****/
////////////////////////////////////////////////
/*		Main Window All Components	 		*/
////////////////////////////////////////////////
//	Label: Status that won't change text.
#define STATUSLABEL1		0x0010
#define STATUSLABEL1_TITLE	"Status:"
//	Label: Status that will change.
#define STATUSLABEL2		0x0020
#define STATUSLABEL2_TITLE	"Secured"
//	Button: CopyRights
#define COPYRIGHTSBTN		0x0030
#define COPYRIGHTSBTN_TITLE "CopyRight"
#define COPYRIGHTSDIALOG	0x0031
#define COPYRIGHTSMSG		"CopyRight (c) 2017 ramb0"
//	Button: Windows Firewall
#define WINDOWS_FIREWALLBTN	0x0032
//	Button: NetworkCTRL
#define NETWORKCTRL_BTN		0x0033
//	Button: Custom Firewall
#define CUSTOMFIREWALL_BTN	0x0034

////////////////////////////////////////////////
/*		NetstatDialog All Components		*/
////////////////////////////////////////////////
#define DIALOG_LABEL		0x0050
#define DIALOG_LABELTEXT	"Network Statics"
//	Listbox:
#define LISTBOX_ESTABLISHED	0x0040
#define LISTBOX_LISTENING	0x0041
//	Label: Listbox type
#define LISTBOX_LABEL1		0x0042
#define LISTBOX_LABEL2		0x0043
//	Label: Listboxes
#define LISTBOX_LABEL1_TEXT	"LISTENING"
#define LISTBOX_LABEL2_TEXT	"ESTABLISHED"
//	Label: Process ID
#define LABEL_INFO			0x0044
#define LABEL_INFO_TEXT		"Process ID: "
//	Label: Process ID
#define PROCESS_LABEL		0x0045
#define PROCESS_LABELTEXT	"Unknown"
//	Button: Kill Process
#define KILLPROCESS_BTN		0x0046
#define KILLPROCESS_TEXT	"Kill Process"
#define GETNETSTATICS_BTN	0x0047
//	Label: information connection
#define CONN_INFO			0x0048
//	Label: information connection
#define LABEL_CONN_INFO		0x0049
//	Button: Outgoing and incoming connections
#define NETSTAT_BTN			0x0050
#define NETSTAT_BTN_TEXT	"Network Statics"
//	Label: Process name
#define PROCESSNAME_LABEL	0x0051
#define PROCESSNAME_INFO	0x0052
//	Button: File Location
#define FILELOCATION_BTN	0x0053

////////////////////////////////////////////////
/*		Windows Firewall Dialog Components	*/
////////////////////////////////////////////////
#define LABELWFIREWALL		0x0060
#define DOMAINPROFILELBL	0x0061
#define PRIVATEPROFILELBL	0x0062
#define PUBLICPROFILELBL	0x0063
//	DATA LABELS
#define FWSTATE1			0x0070
#define FWSTATE2			0x0071
#define FWSTATE3			0x0072
#define BLOCKINBOUND1		0x0073
#define BLOCKINBOUND2		0x0074
#define BLOCKINBOUND3		0x0075
#define UNICASTRES1			0x0076
#define UNICASTRES2			0x0077
#define UNICASTRES3			0x0078
#define DEFINBOUNDAC1		0x0079
#define DEFINBOUNDAC2		0x0080
#define DEFINBOUNDAC3		0x0081
#define DEFOUTBOUNDAC1		0x0082
#define DEFOUTBOUNDAC2		0x0083
#define DEFOUTBOUNDAC3		0x0084
#define NOTIFICATIONS1		0x0085
#define NOTIFICATIONS2		0x0086
#define NOTIFICATIONS3		0x0087


////////////////////////////////////////////////
/*		Network Control Dialog Components	*/
////////////////////////////////////////////////
#define LISTBOX_ONLINEDEV	0x0090
#define LABEL_ONLINEDEV		0x0091
#define LISTBOX_UNKNOWNDEV	0x0092
#define LABEL_UNKNOWNDEV	0x0093
#define LISTBOX_FILE		0x0094
#define LABEL_FILELISTBOX	0x0095
#define LABEL_ADDDEVICES	0x0096
#define LABEL_DELETEDEVICE	0x0097
#define EDIT_FRIENDLYNAME	0x0098
#define EDIT_MACADDR		0x0099
#define EDIT_IPADDR			0x0100
#define BTN_ADDFRIENDLYDEV	0x0101
#define BTN_DELFRIENDLYDEV	0x0102
#define SELECTED_DEV		0x0103

////////////////////////////////////////////////
/*		Custom Firewall Dialog Components	*/
////////////////////////////////////////////////
#define LABEL_TEXT			0x0104
#define STATUS_LABEL		0x0105
#define STATUS_LABEL2		0x0106
#define ONOFF_BTN			0x0107
#define LABELBLOCKEDIP		0x0108
#define BLOCKEDIP_LISTBOX	0x0109
#define RULE_LABEL			0x0110
#define RULETODELETE_LABEL	0x0111
#define DELETERULE_BTN		0x0112
#define IPADDR_TEXTBOX		0x0113
#define ADDRULE_BTN			0x0114
#define ADDRULE_LABEL		0x0115



////////////////////////////////////////////////
/*		Action Window Components			*/
////////////////////////////////////////////////
#define LABEL_MACADDR		0x0116
#define LABEL_HOSTNAME		0x0117
#define LABEL_IPADDR		0x0118
#define BTN_REMOVELISTBOX	0x0119
#define BTN_BLOCKIP			0x0120
#define BTN_ADDFRIENDLYLIST	0x0121

////////////////////////////////////////////////
/*		Action Window 2 Components			*/
////////////////////////////////////////////////



//	Client Resource
#define CLIENT_NAME				L"Intrusion Protection System"
#define CLIENT_MAJOR_VER		1
#define CLIENT_MINOR_VER		0
#define CLIENT_REVISION			2