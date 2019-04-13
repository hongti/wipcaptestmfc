
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
	u_char  ihl;            // 版本+首部长度   
	u_char  tos;            // 服务类型(Type of service) 
	u_short tlen;           // 总长(Total length) 
	u_short identification; // 标识(Identification)
	u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	u_char  ttl;            // 存活时间(Time to live)
	u_char  proto;          // 协议(Protocol)
	u_short crc;            // 首部校验和(Header checksum)
	ip_address  saddr;      // 源地址(Source address)
	ip_address  daddr;      // 目的地址(Destination address)
}ip_header;

/* UDP 首部*/
typedef struct udp_header {
	u_short sport;          // 源端口(Source port)
	u_short dport;          // 目的端口(Destination port)
	u_short len;            // UDP数据包长度(Datagram length)
	u_short crc;            // 校验和(Checksum)
}udp_header;

typedef struct tcp_header {
	u_short sport;         /* source port */
	u_short dport;         /* destination port */
	u_int seq;             /* sequence number */
	u_int ack;             /* acknowledgement number */
	u_char  reserved_1;
	u_char  thl;        
	u_char  flag;       
	u_char  reseverd_2;
	u_short window;        /* window */
	u_short sum;           /* checksum */
	u_short urp;           /* urgent pointer */
}tcp_header;

typedef struct ethernet_header{
	u_char   dest_mac[6];
	u_char   src_mac[6];
	u_short  eth_type;
}ethernet_header;


//void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

pcap_if_t *alldevs;
pcap_if_t *d;
int inum;
int i = 0;
int res;
pcap_t *adhandle;
char errbuf[PCAP_ERRBUF_SIZE];
//u_int netmask;
//char packet_filter[] = "ip and udp";
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

	pCtrl->AddString((CString) "listening on " + (CString)d->description + (CString)"...");

	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	AfxBeginThread(Thread, this, THREAD_PRIORITY_IDLE);
}

UINT CmfctestDlg::Thread(void *param)
{
	CmfctestDlg *dlg = (CmfctestDlg*)param;
	CListBox *pCtrl = (CListBox *)dlg->GetDlgItem(IDC_LIST2);
	CString messageonlist2;
	CStatic *pStext = (CStatic *)dlg->GetDlgItem(IDC_STATIC);
	CString pakect_num;

	/* 获取数据包 */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* 超时时间到 */
			continue;

		u_short ethernet_type;//                                     /*以太网协议类型*/
		ethernet_header *ethernet_protocol;//  /*以太网协议变量*/
		u_char *mac_string;
		static int packet_number = 1;
		messageonlist2.Format(_T("第【%d】个IP数据包被捕获"), packet_number);

		pCtrl->AddString(messageonlist2);
		pCtrl->AddString(_T("#链路层(以太网协议)"));

		ethernet_protocol = (ethernet_header *)pkt_data;//  /*获得一太网协议数据内容*/
		ethernet_type = ntohs(ethernet_protocol->eth_type); /*获得以太网类型*/
		messageonlist2.Format(_T("##以太网类型为 : %04x"), ethernet_type);
		pCtrl->AddString(messageonlist2);

		switch (ethernet_type)//            /*判断以太网类型的值*/
		{
		case 0x0800:
			pCtrl->AddString(_T("####网络层是：IPv4协议")); break;
		case 0x0806:
			pCtrl->AddString(_T("####网络层是：ARP协议")); break;
		case 0x8035:
			pCtrl->AddString(_T("####网络层是：RARP协议")); break;
		default: break;
		}
		/*获得Mac源地址*/
		mac_string = ethernet_protocol->src_mac;
		messageonlist2.Format(_T("####Mac源地址:%02x:%02x:%02x:%02x:%02x:%02x:\n"), *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
		pCtrl->AddString(messageonlist2);

		/*获得Mac目的地址*/
		mac_string = ethernet_protocol->dest_mac;
		messageonlist2.Format(_T("####Mac目的地址:%02x:%02x:%02x:%02x:%02x:%02x:\n"), *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
		pCtrl->AddString(messageonlist2);

		if (ethernet_type == 0x0800) {
			//        /*如果上层是IPv4ip协议,就调用分析ip协议的函数对ip包进行贩治*/ 
			struct ip_header *ip_protocol;//   /*ip协议变量*/
			u_int header_length;//    /*长度*/
			u_int offset;//                   /*片偏移*/
			u_int16_t checksum;//    /*首部检验和*/
			ip_protocol = (struct ip_header*)(pkt_data + 14); /*获得ip数据包的内容去掉以太头部*/
			checksum = ntohs(ip_protocol->crc);//      /*获得校验和*/
			offset = ntohs(ip_protocol->flags_fo);//   /*获得偏移量*/
			header_length = ip_protocol->ihl * 4;
			pCtrl->AddString(_T("##网络层（IP协议）"));
			messageonlist2.Format(_T("####IP版本:IPv4"));
			pCtrl->AddString(messageonlist2);
			messageonlist2.Format(_T("####IP协议首部长度:%d"), header_length);
			pCtrl->AddString(messageonlist2);
			messageonlist2.Format(_T("####服务类型:%d"), ip_protocol->tos);
			pCtrl->AddString(messageonlist2);
			messageonlist2.Format(_T("####总长度:%d"), ntohs(ip_protocol->tlen));/*获得总长度*/
			pCtrl->AddString(messageonlist2);
			messageonlist2.Format(_T("####标识:%d"), ntohs(ip_protocol->identification));/*获得标识*/
			pCtrl->AddString(messageonlist2);
			messageonlist2.Format(_T("####片偏移:%d"), (offset & 0x1fff) * 8);
			pCtrl->AddString(messageonlist2);
			messageonlist2.Format(_T("####生存时间:%d"), ip_protocol->ttl);
			pCtrl->AddString(messageonlist2);
			messageonlist2.Format(_T("####首部检验和:%d"), checksum);
			pCtrl->AddString(messageonlist2);
			messageonlist2.Format(_T("####源IP:%d.%d.%d.%d"), ip_protocol->saddr.byte1, ip_protocol->saddr.byte2, ip_protocol->saddr.byte3, ip_protocol->saddr.byte4);//          /*获得源ip地址*/
			pCtrl->AddString(messageonlist2);
			messageonlist2.Format(_T("####目的IP:%d.%d.%d.%d"), ip_protocol->daddr.byte1, ip_protocol->daddr.byte2, ip_protocol->daddr.byte3, ip_protocol->daddr.byte4);/*获得目的ip地址*/
			pCtrl->AddString(messageonlist2);
			printf("协议号:%d", ip_protocol->proto);//         /*获得协议类型*/
			pCtrl->AddString(messageonlist2);
			pCtrl->AddString(_T("##传输层协议是:"));
			if (ip_protocol->proto == 6)
			{
				pCtrl->AddString(_T("####TCP"));
				struct tcp_header *tcp_protocol;//     /*tcp协议变量*/
				u_char flags;//                          /*标记*/
				int header_length;//                  /*头长度*/
				u_short source_port;//           /*源端口*/
				u_short destination_port;//   /*目的端口*/
				u_short windows;//                /*窗口大小*/
				u_short urgent_pointer;//     /*紧急指针*/
				u_int sequence;//                 /*序列号*/
				u_int acknowledgement;//   /*确认号*/
				u_int16_t checksum;//       /*检验和*/
				tcp_protocol = (struct tcp_header *) (pkt_data + 14 + 20);//  /*获得tcp首部内容*/
				source_port = ntohs(tcp_protocol->sport);//                  /*获得源端口号*/
				destination_port = ntohs(tcp_protocol->dport); /*获得目的端口号*/
				sequence = ntohl(tcp_protocol->seq);//        /*获得序列号*/
				acknowledgement = ntohl(tcp_protocol->ack);
				windows = ntohs(tcp_protocol->window);
				urgent_pointer = ntohs(tcp_protocol->urp);
				flags = tcp_protocol->flag;
				checksum = ntohs(tcp_protocol->sum);
				pCtrl->AddString(_T("####运输层（TCP协议）"));
				messageonlist2.Format(_T("####源端口：%d"), source_port);
				pCtrl->AddString(messageonlist2);
				messageonlist2.Format(_T("####目的端口：\t %d\n"), destination_port);
				pCtrl->AddString(messageonlist2);

				int min = (destination_port < source_port) ? destination_port : source_port;
				pCtrl->AddString(_T("##应用层协议是："));
				switch (min)
				{
				case 80: {messageonlist2.Format(_T("#### http 用于万维网（WWW）服务的超文本传输协议（HTTP）"));
					break; }

				case 21: {messageonlist2.Format(_T("#### ftp 文件传输协议（FTP）"));
					break; }

				case 23: {messageonlist2.Format(_T("#### telnet Telnet 服务  "));
					break; }

				case 25: {messageonlist2.Format(_T("#### smtp 简单邮件传输协议（SMTP）"));
					break; }

				case 110: {messageonlist2.Format(_T("#### pop3 邮局协议版本3 "));
					break; }
				case 443: {messageonlist2.Format(_T("#### https 安全超文本传输协议（HTTP） "));
					break; }

				default: {messageonlist2.Format(_T("####【其他类型】 "));
					break; }
				}
				messageonlist2.Format(_T("####序列号：%u"), sequence);
				pCtrl->AddString(messageonlist2);
				messageonlist2.Format(_T("####确认号：%u"), acknowledgement);
				pCtrl->AddString(messageonlist2);
				messageonlist2.Format(_T("####保留字段：%d"), tcp_protocol->reserved_1);
				pCtrl->AddString(messageonlist2);

				if (flags & 0x08) pCtrl->AddString(_T("####控制位：【推送 PSH】"));
				if (flags & 0x10) pCtrl->AddString(_T("####控制位：【确认 ACK】"));
				if (flags & 0x02) pCtrl->AddString(_T("####控制位：【同步 SYN】"));
				if (flags & 0x20) pCtrl->AddString(_T("####控制位：【紧急 URG】"));
				if (flags & 0x01) pCtrl->AddString(_T("####控制位：【终止 FIN】"));
				if (flags & 0x04) pCtrl->AddString(_T("####控制位：【复位 RST】"));

				messageonlist2.Format(_T("####窗口大小 :%d"), windows);
				pCtrl->AddString(messageonlist2);
				messageonlist2.Format(_T("####检验和 :%d"), checksum);
				pCtrl->AddString(messageonlist2);
				messageonlist2.Format(_T("####紧急指针字段 :%d"), urgent_pointer);
				pCtrl->AddString(messageonlist2);
				/*协议类型是6代表TCP*/
			}
			else if (ip_protocol->proto == 17) {
				pCtrl->AddString(_T("UDP"));
				/*17代表UDP*/
			}
			else if (ip_protocol->proto == 1) {
				pCtrl->AddString(_T("ICMP"));
				/*代表ICMP*/
			}
			else if (ip_protocol->proto == 2) {
				pCtrl->AddString(_T("IGMP"));
				/*代表IGMP*/
			}
		}

		packet_number++;

		pakect_num.Format(_T("当前抓取第%d个IP包！"), packet_number);
		pStext->SetWindowText(pakect_num);

		if (res == -1) {
			exit(1);
		}
	}
}



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