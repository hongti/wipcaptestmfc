
// mfctestDlg.h: 头文件
//

#pragma once


// CmfctestDlg 对话框
class CmfctestDlg : public CDialogEx
{
// 构造
public:
	CmfctestDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCTEST_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	static UINT Thread(void * param);
	DECLARE_MESSAGE_MAP()
public:
//	CButton my_string;
	afx_msg void OnClickedButton2();
//	CEdit my_cstring;
	CString my_cstring;
	afx_msg void OnClickedButton1();
};
