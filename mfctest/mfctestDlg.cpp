
// mfctestDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "mfctest.h"
#include "mfctestDlg.h"
#include "afxdialogex.h"
#define HAVE_REMOTE
#include <pcap.h>
#include "remote-ext.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,"wpcap.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

/* 4字节的IP地址 */
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 首部 */
typedef struct ip_header {
	u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
	u_char  tos;            // 服务类型(Type of service) 
	u_short tlen;           // 总长(Total length) 
	u_short identification; // 标识(Identification)
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 存活时间(Time to live)
	u_char  proto;          // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_address  saddr;      // 源地址(Source address)
	ip_address  daddr;      // 目的地址(Destination address)
	u_int   op_pad;         // 选项与填充(Option + Padding)
}ip_header;

/* UDP 首部*/
typedef struct udp_header {
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_short len;            // UDP数据包长度(Datagram length)
	u_short crc;            // 校验和(Checksum)
}udp_header;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

pcap_if_t *alldevs;
pcap_if_t *d;
int inum;
int i = 0;
int res;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
u_int netmask;
char packet_filter[] = "ip and udp";
struct bpf_program fcode;
struct pcap_pkthdr *header;
const u_char *pkt_data;


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CmfctestDlg 对话框



CmfctestDlg::CmfctestDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCTEST_DIALOG, pParent)
	, my_cstring(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CmfctestDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	//  DDX_Control(pDX, IDC_BUTTON2, my_string);
	//  DDX_Control(pDX, IDC_EDIT1, my_cstring);
	DDX_Text(pDX, IDC_EDIT1, my_cstring);
}

BEGIN_MESSAGE_MAP(CmfctestDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON2, &CmfctestDlg::OnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON1, &CmfctestDlg::OnClickedButton1)
	ON_WM_TIMER()
END_MESSAGE_MAP()


// CmfctestDlg 消息处理程序

BOOL CmfctestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CmfctestDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CmfctestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CmfctestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CmfctestDlg::OnClickedButton2()
{
	CListBox *pCtrl = (CListBox *)GetDlgItem(IDC_LIST2);
	CString str;
	GetDlgItem(IDC_EDIT1)->GetWindowText(str);
	inum = _ttoi(str);

	if (inum < 1 || inum > i)
	{
		MessageBox((CString)"Interface number out of range.");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
	}

	/* 跳转到选中的适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* 打开设备 */
	if ((adhandle = pcap_open(d->name,          // 设备名
		65535,            // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		CString message = (CString)"Unable to open the adapter. " + (CString)d->name + (CString)" is not supported by WinPcap";
		MessageBox(message);
		//fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		exit(1);
	}

	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		CString message = (CString)"This program works only on Ethernet networks.";
		MessageBox(message);
		//fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		exit(1);
	}

	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;


	//编译过滤器
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		CString message = (CString)"Unable to compile the packet filter. Check the syntax.";
		MessageBox(message);
		//fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		exit(1);
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		CString message = (CString)"Error setting the filter.";
		MessageBox(message);
		//fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		exit(1);
	}

	pCtrl->AddString((CString) "listening on " + (CString)d->description + (CString)"...");

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	/* 开始捕获 */
	//pcap_loop(adhandle, 0, packet_handler, NULL);

	AfxBeginThread(Thread, this, THREAD_PRIORITY_IDLE);
}

UINT CmfctestDlg::Thread(void *param)
{
	CmfctestDlg *dlg = (CmfctestDlg*)param;
	CListBox *pCtrl = (CListBox *)dlg->GetDlgItem(IDC_LIST2);
	CString messageonlist2;

	/* 获取数据包 */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		ip_header *ih;
		udp_header *uh;
		time_t local_tv_sec;
		u_int ip_len;
		u_short sport, dport;
		struct tm now_time;
		char timestr[16];

		if (res == 0)
			/* 超时时间到 */
			continue;

		///* 将时间戳转换成可识别的格式 */
		//local_tv_sec = header->ts.tv_sec;
		//localtime_s(&now_time, &local_tv_sec);
		//strftime(timestr, sizeof timestr, "%H:%M:%S", &now_time);
		//
		CString nowtime;
		CTime time = CTime::GetCurrentTime();
		nowtime = time.Format(_T("%H:%M:%S "));

		CString len;
		len.Format(_T("%.6d len:%d "), header->ts.tv_usec, header->len);
		//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);

		ih = (ip_header *)(pkt_data +
			14); //以太网头部长度

		/* 获得UDP首部的位置 */
		ip_len = (ih->ver_ihl & 0xf) * 4;
		uh = (udp_header *)((u_char*)ih + ip_len);

		/* 将网络字节序列转换成主机字节序列 */
		sport = ntohs(uh->sport);
		dport = ntohs(uh->dport);

		/* 获得IP数据包头部的位置 */
		ih = (ip_header *)(pkt_data +
			14); //以太网头部长度

		/* 获得UDP首部的位置 */
		ip_len = (ih->ver_ihl & 0xf) * 4;
		uh = (udp_header *)((u_char*)ih + ip_len);

		/* 将网络字节序列转换成主机字节序列 */
		sport = ntohs(uh->sport);
		dport = ntohs(uh->dport);

		CString ipudp;
		ipudp.Format(_T("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d"),
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			sport,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			dport);

		messageonlist2 = nowtime + len + ipudp;
		pCtrl->AddString(messageonlist2);
	}

	if (res == -1) {
		exit(1);
	}
}

//此处不使用回调函数，否则将导致程序死锁
//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
//{
//
//	char timestr[16];
//	struct tm now_time;
//	ip_header *ih;
//	udp_header *uh;
//	u_int ip_len;
//	u_short sport, dport;
//	time_t local_tv_sec;
//
//	//将localtime修改为可使用的localtime_s
//	/* 将时间戳转换成可识别的格式 */
//	local_tv_sec = header->ts.tv_sec;
//	localtime_s(&now_time, &local_tv_sec);
//	strftime(timestr, sizeof timestr, "%H:%M:%S", &now_time);
//
//	printf("%s,%.6ld len:%d\n", timestr, header->ts.tv_usec, header->len);
//
//	/* 获得IP数据包头部的位置 */
//	ih = (ip_header *)(pkt_data +
//		14); //以太网头部长度
//
//	/* 获得UDP首部的位置 */
//	ip_len = (ih->ver_ihl & 0xf) * 4;
//	uh = (udp_header *)((u_char*)ih + ip_len);
//
//	/* 将网络字节序列转换成主机字节序列 */
//	sport = ntohs(uh->sport);
//	dport = ntohs(uh->dport);
//
//	/* 打印IP地址和UDP端口 */
//	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
//		ih->saddr.byte1,
//		ih->saddr.byte2,
//		ih->saddr.byte3,
//		ih->saddr.byte4,
//		sport,
//		ih->daddr.byte1,
//		ih->daddr.byte2,
//		ih->daddr.byte3,
//		ih->daddr.byte4,
//		dport);
//}


void CmfctestDlg::OnClickedButton1()
{
	CListBox *pCtrl = (CListBox *)GetDlgItem(IDC_LIST1);

	/* 获取本机设备列表 */
	if (pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		CString num;
		num.Format(_T("%d"), ++i);
		CString name = num + "." + (CString)d->name;
		if (d->description) {
			CString decription = name + (CString)d->description;
			pCtrl->AddString(decription);
			//printf(" (%s)\n", d->description);
		}
		else
			pCtrl->AddString((CString)" (No description available)");
		//printf(" (No description available)\n");
	}

	if (i == 0)
	{
		pCtrl->AddString((CString)"No interfaces found! Make sure WinPcap is installed.");
	}

}


