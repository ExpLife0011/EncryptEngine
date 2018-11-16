#include "process.h"
#include "..\include\iocommon.h"
#include "..\include\interface.h"

ULONG g_nProcessNameOffset = 0 ;
LIST_ENTRY g_ProcessListHead ;
KSPIN_LOCK g_ProcessListLock ;

static BOOLEAN Psi_SetProcessMonitor(PPROCESS_INFO psProcInfo, BOOLEAN bAll) ;
static BOOLEAN Psi_SearchForSpecifiedProcessInList(PUCHAR pszProcessName, BOOLEAN bRemove,BOOLEAN bMonitor) ;
static ULONG   Psi_AddProcessInfo(PUCHAR pszProcessName, BOOLEAN bMonitor) ;
static ULONG   Psi_DelProcessInfo(PUCHAR pszProcessName, BOOLEAN bMonitor) ;

/*
* 根据参数二提供的进程ID在进程链表中添加进程信息，默认的进程状态是未启用。
* 参数一未使用
* 参数三必须为真，当前未使用
*/
VOID Ps_ProcessCallBack(
	__in HANDLE hParentId,
	__in HANDLE hProcessId,
	__in BOOLEAN bCreate
	)
{
	NTSTATUS status = STATUS_SUCCESS ;
	PEPROCESS EProcess ;
	UCHAR szProcessName[16] = {0} ;	

	UNREFERENCED_PARAMETER(bCreate) ;
	UNREFERENCED_PARAMETER(hParentId) ;

	try{

		if (!bCreate)
			_leave ;

		/**
		 * get process environment block(PEB)
		 *  The PsLookupProcessByProcessId routine accepts the process ID of a process and returns a 
		 *  referenced pointer to EPROCESS structure of the process.
		 */
		status = PsLookupProcessByProcessId(hProcessId, &EProcess) ;
		if (!NT_SUCCESS(status))
		{
			_leave ;
		}

		/**
		 * get process name
		 */
		//Ps_GetProcessName(szProcessName, EProcess) ;

		/**
		 * add process info in list, if exists, donnot insert into list again.
		 */
		//Psi_AddProcessInfo(szProcessName, FALSE) ;

	}
	finally{
		/**/
		//Todo some post work here
	}
}

/*
 * 检测当前进程是否被监控。
 */
extern KSPIN_LOCK	g_SpinLockForProcessRecognition;
WCHAR wszFilePathName[512];
CHAR szProcessName[64];
BOOLEAN Ps_IsCurrentProcessMonitored(WCHAR* pwszFilePathName, ULONG uLength, BOOLEAN* bIsSystemProcess, BOOLEAN* bIsPPTFile)
{
	KIRQL irql;
	int nIndex = 0;
	BOOLEAN bRet = FALSE ;
	BOOLEAN bExcelExt = FALSE ;
	WCHAR* pwszExt = NULL ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;
	
	KeAcquireSpinLock(&g_SpinLockForProcessRecognition, &irql);
	
	try{
		// get current process name. 

		RtlZeroMemory(szProcessName,64);
		Ps_GetProcessName(szProcessName, NULL) ;
		

		// save file path name in local buffer

		RtlZeroMemory(wszFilePathName,1024);
		RtlCopyMemory(wszFilePathName, pwszFilePathName, uLength*sizeof(WCHAR)) ;

		// recognize process name and return to caller
		if (bIsSystemProcess != NULL)
		{
			/* 由于任何地方都没有用到SYSTEM_PROCESS宏，所以先注释掉~
		    if ((strlen(szProcessName) == strlen("explorer.exe")) && !_strnicmp(szProcessName, "explorer.exe", strlen("explorer.exe")))
			{
				*bIsSystemProcess = SYSTEM_PROCESS ;
			}
			else
			{*/
				
		    	if ((strlen(szProcessName) == strlen("excel.exe")) && !_strnicmp(szProcessName, "excel.exe", strlen("excel.exe")))
				{
					*bIsSystemProcess = EXCEL_PROCESS ;
					
				}
		    	else if ((strlen(szProcessName) == strlen("powerpnt.exe")) && !_strnicmp(szProcessName, "powerpnt.exe", strlen("powerpnt.exe")))
				{
					*bIsSystemProcess = POWERPNT_PROCESS ;
				}else
				{
					*bIsSystemProcess = NORMAL_PROCESS ;
				}
				
				//测试看看能否解决 et.exe 把加密的 Excel 创建的文件自动解密的问题，并结合DebugView输出调试下~
				if ((strlen(szProcessName) == strlen("et.exe")) && !_strnicmp(szProcessName, "et.exe", strlen("et.exe")))
				{
					*bIsSystemProcess = EXCEL_PROCESS ;
				}


			//}
		}

		//将路径转换为小写字母
		_wcslwr(wszFilePathName) ;	
		//DbgPrint("wszFilePathName in Ps_IsCurrentProcessMonitored :%S \n", wszFilePathName);	

		//当前文件如果出现在系统临时文件夹，那么直接返回真，表示应该监视当前进程
		if (wcsstr(wszFilePathName, L"\\local settings\\temp"))//\Local Settings\Temp
		{
#ifdef DBG
			DbgPrint("当前文件出现系统临时目录直接返回真，应该监视当前进程 in Ps_IsCurrentProcessMonitored  \\local settings\\temp=true\n");
#endif
			bRet = TRUE ;
			__leave ;
		}
		
		// go to end of file path name, save pointer in pwszExt
		pwszExt = wszFilePathName + uLength - 1 ;//pwszExt 保存指向了最后一个字符的地址

		// verify file attribute, if directory, return false
		if (pwszFilePathName[uLength-1] == L'\\')//.\目录的样式
		{//if directory, filter it
			bRet = FALSE ;
#ifdef DBG
			//DbgPrint("It is a dir:False\n");	
#endif
			__leave ;
		}

		// redirect to file extension name(including point)
		//(((pwszExt != wszFilePathName) && (*pwszExt != L'\\'))指没到第一个字符和不是\的时候
		while (((pwszExt != wszFilePathName) && (*pwszExt != L'\\')) && ((*pwszExt) != L'.')) //定向至扩展名
		{//direct into file extension
			pwszExt -- ;
		}
		//JK pwszExt要么指向. 要么指向\  指向\就是没有扩展名的意思
		// verify this is a file without extension name
		if ((pwszExt == wszFilePathName) || (*pwszExt == L'\\'))
		{//no file extension exists in input filepath name, filter it.
			bRet = FALSE ;
#ifdef DBG
			//DbgPrint("It has no ext:False\n");	
#endif
			/*
			if((*pwszExt == L'\\') && ((strlen(szProcessName) == strlen("excel.exe")) && !_strnicmp(szProcessName, "excel.exe", strlen("excel.exe"))))
			{
				bRet = TRUE ;//加上后依然不好用~
			}*/

			if((( pwszExt != wszFilePathName) && (*pwszExt == L'\\')) && !_strnicmp(szProcessName, "excel.exe", strlen("excel.exe")))
			{
				DbgPrint("excel.exe and no ext file ~~~\n");
				bExcelExt = TRUE;
			}else
			{
				__leave ;
			}
/*
			if((( pwszExt != wszFilePathName) && (*pwszExt == L'\\')) && !_strnicmp(szProcessName, "et.exe", strlen("et.exe")))
			{
				DbgPrint("et.exe and no ext file ~~~\n");
				bExcelExt = TRUE;
			}else
			{
				__leave ;
			}
*/			
		}
	
		// verify tmp file
		if(!_strnicmp(szProcessName, "powerpnt.exe", strlen("powerpnt.exe")))
		if ((bIsPPTFile != NULL) && !_wcsnicmp(pwszExt, L".ppt", wcslen(L".ppt")))
		{
			*bIsPPTFile = TRUE ;//为实参赋值，因为实参是一个空布尔型变量的地址
		}

		// verify tmp file
		if(!_strnicmp(szProcessName, "powerpnt.exe", strlen("powerpnt.exe")))
		if ((bIsPPTFile != NULL) && !_wcsnicmp(pwszExt, L".pptx", wcslen(L".pptx")))
		{
			*bIsPPTFile = TRUE ;//为实参赋值，因为实参是一个空布尔型变量的地址
		}
		

		// verify tmp file
		if(!_strnicmp(szProcessName, "powerpnt.exe", strlen("powerpnt.exe")))
		if ((bIsPPTFile != NULL) && !_wcsnicmp(pwszExt, L".tmp", wcslen(L".tmp")))
		{
			*bIsPPTFile = TRUE ;//为实参赋值，因为实参是一个空布尔型变量的地址
		}

		// compare current process name with process info in monitored list
		// if existing, match file extension name
		TmpListEntryPtr = g_ProcessListHead.Flink ;
		
		while(&g_ProcessListHead != TmpListEntryPtr)
		{
			psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;

			if(!_strnicmp(psProcessInfo->szProcessName, szProcessName, strlen(szProcessName)))//if(1)//先匹配进程名再匹配扩展名
			{
				nIndex = 0 ;
				//DbgPrint("ProcessName is equal,pwszExt is %ws\n",pwszExt);//判断当前文件扩展名是否是匹配的，根据每个进程的扩展名列表来进行匹配


				if (!_strnicmp(psProcessInfo->szProcessName, "excel.exe", strlen("excel.exe")))
				{
					if (bExcelExt==TRUE)
					{
						//bRet = TRUE;//psProcessInfo->bMonitor ;//FOR TEST!
						//if (psProcessInfo->bMonitor == TRUE)
						//{
							bRet = TRUE;//觉得就没必要再判断bMonitor了，因为已经在进程列表中了，而进程列表中就默认都是机密进程。
							DbgPrint("*****TRUE*** szProcessName is Excel.exe,extension is null~~~ \n");
						//}

						__leave ;
					}
				}

				if (!_strnicmp(psProcessInfo->szProcessName, "et.exe", strlen("et.exe")))
				{
					if (bExcelExt==TRUE)
					{
						//bRet = TRUE;//psProcessInfo->bMonitor ;//FOR TEST!
						//if (psProcessInfo->bMonitor == TRUE)
						//{
						bRet = TRUE;//觉得就没必要再判断bMonitor了，因为已经在进程列表中了，而进程列表中就默认都是机密进程。
						DbgPrint("*****TRUE*** szProcessName is ET.exe,extension is null~~~ \n");
						//}

						__leave ;
					}
				}


				
				while (TRUE)//判断当前文件扩展名是否是匹配的，根据每个进程的扩展名列表来进行匹配
				{
					// judge whether current file extension name is matched with monitored file type in list
					if (psProcessInfo->wsszRelatedExt[nIndex][0] == L'\0')//用于退出扩展名的比较循环
					{						
						bRet = FALSE ;
						break ;
					}
					else if ((wcslen(pwszExt) == wcslen(psProcessInfo->wsszRelatedExt[nIndex])) && !_wcsnicmp(pwszExt, psProcessInfo->wsszRelatedExt[nIndex], wcslen(pwszExt)))
					{
						bRet = TRUE;//既然找到就说明匹配上了，所以直接返回True即可。psProcessInfo->bMonitor;//bRet = TRUE;//psProcessInfo->bMonitor ;//FOR TEST!
						DbgPrint("***TRUE***** szProcessName is %s,extension matched:%u File pwszExt is %ws\n",szProcessName,bRet,pwszExt);
						__leave ;
						
					}
					nIndex ++ ;
				}				
			}

			// move to next process info in list
			TmpListEntryPtr = TmpListEntryPtr->Flink ;
	}
		
		//DbgPrint("Nothing to compare ~ \n");
		
		bRet = FALSE ;
	}
	finally{
		/**/
		//Todo some post work here
	}
	KeReleaseSpinLock(&g_SpinLockForProcessRecognition, irql);
	return bRet ;
}


/*
 * 获取驱动当前维护的进程监控列表，此函数没有检测可供使用的缓冲区大小，存在安全隐患。
 */
PVOID
Ps_GetAllProcessInfo(
   __out PVOID  pProcessInfo,
   __out PULONG puCount
   )
{
	KIRQL oldIrql ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;
	PMSG_GET_ALL_PROCESS_INFO psGetAllProcInfo = (PMSG_GET_ALL_PROCESS_INFO)pProcessInfo ;

	try{

		*puCount = 0 ;
		KeAcquireSpinLock(&g_ProcessListLock, &oldIrql) ;
		TmpListEntryPtr = g_ProcessListHead.Flink ;
		while(&g_ProcessListHead != TmpListEntryPtr)
		{
			//when it is reply fot IOCTL_GET_PROCESS_COUNT
			if (NULL != psGetAllProcInfo)
			{//get all process info if needed
				psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;
				RtlCopyMemory(psGetAllProcInfo->sProcInfo[*puCount].szProcessName, psProcessInfo->szProcessName, strlen(psProcessInfo->szProcessName)) ;
				psGetAllProcInfo->sProcInfo[*puCount].bMonitor = psProcessInfo->bMonitor ;
				psGetAllProcInfo->uCount ++ ;
			}

			(*puCount) ++ ; //get process count
			TmpListEntryPtr = TmpListEntryPtr->Flink ;
		}

	}
	finally{
		/**/
		//Todo some post work here
		KeReleaseSpinLock(&g_ProcessListLock, oldIrql) ;
	}

	return pProcessInfo ;
}


/*
 * 响应用户消息时用到的设置特定进程监控启用状态的函数
 */
BOOLEAN
Ps_SetProcessInfo(
   __in PVOID InputBuffer
   )
{
	PMSG_SEND_SET_PROCESS_INFO psSendSetProcInfo = (PMSG_SEND_SET_PROCESS_INFO)InputBuffer ;
	try{
		if (NULL == psSendSetProcInfo)
			_leave ;
		if (IOCTL_SET_PROCESS_MONITOR == psSendSetProcInfo->sSendType.uSendType)
		{
			Psi_SetProcessMonitor(&psSendSetProcInfo->sProcInfo, FALSE) ;
		}
	}
	finally{
	}

	return TRUE ;
}


/*
 * 响应用户消息时用到的添加特定进程信息的函数
 */
VOID Ps_AddProcessInfo(PVOID pAddProcInfo, PVOID pAddProcRes)
{
	PMSG_SEND_ADD_PROCESS_INFO psSendAddProcInfo = (PMSG_SEND_ADD_PROCESS_INFO)pAddProcInfo ;
	PMSG_GET_ADD_PROCESS_INFO psGetAddProcInfo = (PMSG_GET_ADD_PROCESS_INFO)pAddProcRes ;

	try{
		if ((NULL == psSendAddProcInfo) || (NULL == psGetAddProcInfo))
		{
			_leave ;
		}
		DbgPrint("******** psSendAddProcInfo->sProcInfo.szProcessName %s\n",psSendAddProcInfo->sProcInfo.szProcessName);
		psGetAddProcInfo->uResult = Psi_AddProcessInfo(psSendAddProcInfo->sProcInfo.szProcessName, TRUE);//psSendAddProcInfo->sProcInfo.bMonitor) ;
	}
	finally{
	}
}

/*
 * 响应用户消息时用到的删除特定进程信息的函数
 */
VOID Ps_DelProcessInfo(PVOID pDelProcInfo, PVOID pDelProcRes)
{
	PMSG_SEND_DEL_PROCESS_INFO psSendDelProcInfo = (PMSG_SEND_DEL_PROCESS_INFO)pDelProcInfo ;
	PMSG_GET_DEL_PROCESS_INFO psGetDelProcInfo = (PMSG_GET_DEL_PROCESS_INFO)pDelProcRes ;

	try{
		if ((NULL == psSendDelProcInfo) || (NULL == psGetDelProcInfo))
		{
			_leave ;
		}
		psGetDelProcInfo->uResult = Psi_DelProcessInfo(psSendDelProcInfo->sProcInfo.szProcessName, psSendDelProcInfo->sProcInfo.bMonitor) ;
	}
	finally{
	}
}


/*
 * 在进程链表中添加新进程的信息，并根据参数二设置启用状态，如果已经存在该进程的信息，则放弃处理。
 */
ULONG Psi_AddProcessInfo(PUCHAR pszProcessName, BOOLEAN bMonitor)
{
	ULONG uRes = MGAPI_RESULT_SUCCESS ;
	PiPROCESS_INFO psProcInfo = NULL ;
	BOOLEAN bRet ;

	try{
		if (NULL == pszProcessName)
		{
			DbgPrint("MGAPI_RESULT_INTERNEL_ERROR\n");
			uRes = MGAPI_RESULT_INTERNEL_ERROR ;
			_leave ;
		}

		/**
		* search for process name, if exists, donnot insert again
		*/
		bRet = Psi_SearchForSpecifiedProcessInList(pszProcessName, FALSE,bMonitor) ;
		if (bRet)
		{
			DbgPrint("MGAPI_RESULT_ALREADY_EXIST pszProcessName %s\n",pszProcessName);
			uRes = MGAPI_RESULT_ALREADY_EXIST ;
			_leave ;
		}

		/**
		* allocate process info structure
		*/
		psProcInfo = ExAllocatePool(NonPagedPool, sizeof(iPROCESS_INFO)) ;
		if (NULL == psProcInfo)
		{
			DbgPrint("******** MGAPI_RESULT_INTERNEL_ERROR\n");
			
			uRes = MGAPI_RESULT_INTERNEL_ERROR ;
			_leave ;
		}

		RtlZeroMemory(psProcInfo, sizeof(iPROCESS_INFO)) ;

		DbgPrint("******** Prepare initialize .... \n");

		/**
		* initialize process info and insert it into global process list
		*/
		if (!_strnicmp(pszProcessName, "winword.exe", strlen("winword.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".html") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".txt") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".mh_") ; //relative to .mht and .mhtml extension
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".rtf") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".ht_") ; //relative to .htm and .html extension
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".xml") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".mht") ;
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".mhtml") ;
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".htm") ;
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".dot") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".tmp") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".docm") ;
			wcscpy(psProcInfo->wsszRelatedExt[12], L".docx") ;
			wcscpy(psProcInfo->wsszRelatedExt[13], L".doc") ;
		}
		else if (!_strnicmp(pszProcessName, "wps.exe", strlen("wps.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0], L".wps") ;
			wcscpy(psProcInfo->wsszRelatedExt[1], L".mpt") ;	
			wcscpy(psProcInfo->wsszRelatedExt[2], L".doc") ;
			wcscpy(psProcInfo->wsszRelatedExt[3], L".dot") ;
			wcscpy(psProcInfo->wsszRelatedExt[4], L".txt") ;
			wcscpy(psProcInfo->wsszRelatedExt[5], L".docx") ;
			wcscpy(psProcInfo->wsszRelatedExt[6], L".tmp") ;
		}
		else if (!_strnicmp(pszProcessName, "excel.exe", strlen("excel.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".xls") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".xml") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".mht") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".mhtml") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".htm") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".html") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".mh_") ; //relative to .mht extension
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".ht_") ; //relative to .htm and .html extension
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".xlt") ;
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".txt") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".tmp") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".") ;
			wcscpy(psProcInfo->wsszRelatedExt[12], L".xlsx") ;
		}
		else if (!_strnicmp(pszProcessName, "et.exe", strlen("et.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0], L".et") ;
			wcscpy(psProcInfo->wsszRelatedExt[1], L".ett") ;	
			wcscpy(psProcInfo->wsszRelatedExt[2], L".xls") ;
			wcscpy(psProcInfo->wsszRelatedExt[3], L".xlt") ;
			wcscpy(psProcInfo->wsszRelatedExt[4], L".txt") ;
			wcscpy(psProcInfo->wsszRelatedExt[5], L".csv") ;
			wcscpy(psProcInfo->wsszRelatedExt[6], L".dbf") ;
			wcscpy(psProcInfo->wsszRelatedExt[7], L".xlsx") ;

		}
		else if (!_strnicmp(pszProcessName, "powerpnt.exe", strlen("powerpnt.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".ppt") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".tmp") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".rtf") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".pot") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".ppsm") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".mht") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".mhtml") ;
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".htm") ;
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".html") ;	
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".pps") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".ppa") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".pptx") ;
			wcscpy(psProcInfo->wsszRelatedExt[12], L".pptm") ;
			wcscpy(psProcInfo->wsszRelatedExt[13], L".potx") ;
			wcscpy(psProcInfo->wsszRelatedExt[14], L".potm") ;
			wcscpy(psProcInfo->wsszRelatedExt[15], L".ppsx") ;
			wcscpy(psProcInfo->wsszRelatedExt[16], L".mh_") ; //relative to .mht and .mhtml extension
			wcscpy(psProcInfo->wsszRelatedExt[17], L".ht_") ; //relative to .htm and .html extension	
			wcscpy(psProcInfo->wsszRelatedExt[18], L".pptx") ;
		}		
		else if (!_strnicmp(pszProcessName, "wpp.exe", strlen("wpp.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".ppt") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".tmp") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".rtf") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".pot") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".ppsm") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".mht") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".mhtml") ;
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".htm") ;
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".html") ;	
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".pps") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".ppa") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".pptx") ;
			wcscpy(psProcInfo->wsszRelatedExt[12], L".pptm") ;
			wcscpy(psProcInfo->wsszRelatedExt[13], L".potx") ;
			wcscpy(psProcInfo->wsszRelatedExt[14], L".potm") ;
			wcscpy(psProcInfo->wsszRelatedExt[15], L".ppsx") ;
			wcscpy(psProcInfo->wsszRelatedExt[16], L".mh_") ; //relative to .mht and .mhtml extension
			wcscpy(psProcInfo->wsszRelatedExt[17], L".ht_") ; //relative to .htm and .html extension	
			wcscpy(psProcInfo->wsszRelatedExt[18], L".pptx") ;
		}
		else if (!_strnicmp(pszProcessName, "System", strlen("System")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".txt") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".docx") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".doc") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".wps") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".dot") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".mpt") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".tmp") ;
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".ppt") ;
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".pptx") ;
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".xls") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".xlsx") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".") ;
			

		}/*
		else if (!_strnicmp(pszProcessName, "explorer.exe", strlen("explorer.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".txt") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".docx") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".doc") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".wps") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".dot") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".mpt") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".tmp") ;
			wcscpy(psProcInfo->wsszRelatedExt[7], L".ppt") ;
			wcscpy(psProcInfo->wsszRelatedExt[8], L".pptx") ;
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".xls") ;
			wcscpy(psProcInfo->wsszRelatedExt[10],  L".xlsx") ;
			wcscpy(psProcInfo->wsszRelatedExt[11],  L".") ;
		}*/
		
		psProcInfo->bMonitor = TRUE;//bMonitor ;
		RtlCopyMemory(psProcInfo->szProcessName, pszProcessName, strlen(pszProcessName)) ;

		//将新建进程信息添加到进程链表
		ExInterlockedInsertTailList(&g_ProcessListHead, &psProcInfo->ProcessList, &g_ProcessListLock) ;
	}
	finally{
	}

	return uRes ;
}



/*************************************************************************
    For Other


	
	
	else if (!_strnicmp(pszProcessName, "notepad.exe", strlen("notepad.exe")))
	{
	wcscpy(psProcInfo->wsszRelatedExt[0],  L".txt") ;
	wcscpy(psProcInfo->wsszRelatedExt[1],  L".log") ;
	}

		else if (!_strnicmp(pszProcessName, "wmplayer.exe", strlen("wmplayer.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".mid") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".rmi") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".midi") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".asf") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".wm") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".wma") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".wmv") ;
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".avi") ;
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".wav") ;
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".mpg") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".mpeg") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".mp2") ;
			wcscpy(psProcInfo->wsszRelatedExt[12], L".mp3") ;
		}

	else if (!_strnicmp(pszProcessName, "photoshop.exe", strlen("photoshop.exe")))
	{

	wcscpy(psProcInfo->wsszRelatedExt[0],  L".psd") ;
	wcscpy(psProcInfo->wsszRelatedExt[1],  L".pdd") ;
	wcscpy(psProcInfo->wsszRelatedExt[2],  L".bmp") ;
	wcscpy(psProcInfo->wsszRelatedExt[3],  L".rle") ;
	wcscpy(psProcInfo->wsszRelatedExt[4], L".dib") ;
	wcscpy(psProcInfo->wsszRelatedExt[5],  L".tif") ;
	wcscpy(psProcInfo->wsszRelatedExt[6], L".crw") ;
	wcscpy(psProcInfo->wsszRelatedExt[7],  L".nef") ;
	wcscpy(psProcInfo->wsszRelatedExt[8],  L".raf") ;
	wcscpy(psProcInfo->wsszRelatedExt[9],  L".orf") ;
	wcscpy(psProcInfo->wsszRelatedExt[10], L".mrw") ;
	wcscpy(psProcInfo->wsszRelatedExt[11], L".dcr") ;
	wcscpy(psProcInfo->wsszRelatedExt[12], L".mos") ;
	wcscpy(psProcInfo->wsszRelatedExt[13], L".raw") ;	
	wcscpy(psProcInfo->wsszRelatedExt[14], L".pef") ;
	wcscpy(psProcInfo->wsszRelatedExt[15], L".srf") ;
	wcscpy(psProcInfo->wsszRelatedExt[16], L".dng") ;
	wcscpy(psProcInfo->wsszRelatedExt[17], L".x3f") ;
	wcscpy(psProcInfo->wsszRelatedExt[18], L".cr2") ;
	wcscpy(psProcInfo->wsszRelatedExt[19], L".erf") ;
	wcscpy(psProcInfo->wsszRelatedExt[20], L".sr2") ;	
	wcscpy(psProcInfo->wsszRelatedExt[21], L".kdc") ;
	wcscpy(psProcInfo->wsszRelatedExt[22], L".mfw") ;	
	wcscpy(psProcInfo->wsszRelatedExt[23], L".mef") ; //relative to .mht extension
	wcscpy(psProcInfo->wsszRelatedExt[24], L".arw") ; //relative to .htm and .html extension
	wcscpy(psProcInfo->wsszRelatedExt[25], L".dcm") ;
	wcscpy(psProcInfo->wsszRelatedExt[26], L".dc3") ;
	wcscpy(psProcInfo->wsszRelatedExt[27], L".dic") ;
	wcscpy(psProcInfo->wsszRelatedExt[28], L".eps") ;
	wcscpy(psProcInfo->wsszRelatedExt[29], L".jpg") ;
	wcscpy(psProcInfo->wsszRelatedExt[30], L".jpeg") ;
	wcscpy(psProcInfo->wsszRelatedExt[31], L".jpe") ;
	wcscpy(psProcInfo->wsszRelatedExt[32], L".pdf") ;
	wcscpy(psProcInfo->wsszRelatedExt[33], L".pdp") ;
	wcscpy(psProcInfo->wsszRelatedExt[34], L".raw") ;
	wcscpy(psProcInfo->wsszRelatedExt[35], L".pct") ;
	wcscpy(psProcInfo->wsszRelatedExt[36], L".pict");			
	wcscpy(psProcInfo->wsszRelatedExt[37], L".mov") ;
	wcscpy(psProcInfo->wsszRelatedExt[38], L".avi") ;
	wcscpy(psProcInfo->wsszRelatedExt[39], L".mpg") ;
	wcscpy(psProcInfo->wsszRelatedExt[40], L".mpeg") ;
	wcscpy(psProcInfo->wsszRelatedExt[41], L".mp4") ;
	wcscpy(psProcInfo->wsszRelatedExt[42], L".m4v") ;
	wcscpy(psProcInfo->wsszRelatedExt[43], L".sct") ;
	wcscpy(psProcInfo->wsszRelatedExt[44], L".psb") ;

	}













*************************************************************************/


/*
 * 在进程链表中删除参数提供的进程名称，参数二目前没有使用，结果表示删除成功与否。
 */
ULONG Psi_DelProcessInfo(PUCHAR pszProcessName, BOOLEAN bMonitor) 
{
	ULONG uRes = MGAPI_RESULT_SUCCESS ;
	BOOLEAN bRet ;

	try{
		if (NULL == pszProcessName)
		{
			uRes = MGDPI_RESULT_INTERNEL_ERROR ;
			_leave ;
		}

		/**
		* search for process name, if exists, donnot insert again
		*/
		bRet = Psi_SearchForSpecifiedProcessInList(pszProcessName, TRUE,bMonitor) ;
		if (!bRet)
		{
			uRes = MGDPI_RESULT_NOT_EXIST ;
			_leave ;
		}
	}
	finally{
	}

	return uRes ;
}


/*
 * 启用所有进程的监控
 */
BOOLEAN
Ps_SetMonitored(
   __in PVOID InputBuffer
   )
{
	PMSG_SEND_SET_PROCESS_INFO psSendSetProcInfo = (PMSG_SEND_SET_PROCESS_INFO)InputBuffer ;
	try{
		if (NULL == psSendSetProcInfo)
			_leave ;
		if (IOCTL_SET_MONITOR == psSendSetProcInfo->sSendType.uSendType)
		{
			//如果第二个参数为真，进程列表中的所有机密进程的是否有效都用第一个参数的bMonitor决定。
			Psi_SetProcessMonitor(&psSendSetProcInfo->sProcInfo, TRUE) ;
		}
	}
	finally{
	}

	return TRUE ;
}

/*
 * 获取特定进程的监控状态
 */
BOOLEAN
Ps_GetMonitorStatus(
   __out PVOID OutputBuffer
   )
{	
	KIRQL oldIrql ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;
	PMSG_SEND_SET_PROCESS_INFO psSendSetProcInfo = (PMSG_SEND_SET_PROCESS_INFO)OutputBuffer ;
	
	try{
		if (NULL == psSendSetProcInfo)
			_leave ;
		KeAcquireSpinLock(&g_ProcessListLock, &oldIrql) ;

		
		TmpListEntryPtr = g_ProcessListHead.Flink ;
		
		while(&g_ProcessListHead != TmpListEntryPtr)
		{
			//获取具体的一个项目
			psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;

			//比较进程名称
			if (!_strnicmp(psProcessInfo->szProcessName, psSendSetProcInfo->sProcInfo.szProcessName, strlen(psSendSetProcInfo->sProcInfo.szProcessName)))
			{	
				//获取进程启用状态
				psSendSetProcInfo->sProcInfo.bMonitor = psProcessInfo->bMonitor ;
				break ;
			}
	
			TmpListEntryPtr = TmpListEntryPtr->Flink ;
		}

		
		KeReleaseSpinLock(&g_ProcessListLock, oldIrql) ;
	}
	finally{
	}

	return TRUE ;
}

/*
 *如果第二个参数为真，则启动进程链表中所有的监控进程，否则就遍历进程列表来找到psProcInfo指向的进程并修改它的状态。
*/
BOOLEAN Psi_SetProcessMonitor(PPROCESS_INFO psProcInfo, BOOLEAN bAll)
{
	BOOLEAN bRet = TRUE ;
	KIRQL oldIrql ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;

	try{

		KeAcquireSpinLock(&g_ProcessListLock, &oldIrql) ;
		TmpListEntryPtr = g_ProcessListHead.Flink ;
		while(&g_ProcessListHead != TmpListEntryPtr)
		{
			psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;

			if (!bAll)
			{
				if (!_strnicmp(psProcessInfo->szProcessName, psProcInfo->szProcessName, strlen(psProcInfo->szProcessName)))
				{
					psProcessInfo->bMonitor = psProcInfo->bMonitor ;
					break ;
				}
			}
			else
			{
				psProcessInfo->bMonitor = psProcInfo->bMonitor ;//如果第二个参数为真，则启动进程链表中所有的监控进程，否则就遍历进程列表来找到psProcInfo指向的进程并修改它的状态。
			}

			TmpListEntryPtr = TmpListEntryPtr->Flink ;
		}

		if(!bAll)
			bRet = FALSE ;
	}
	finally{
		/**/
		//Todo some post work here
		KeReleaseSpinLock(&g_ProcessListLock, oldIrql) ;
	}

	return bRet ;
}


/*
 *find a process in the processlist according to the first parameter, and this item would be deleted if the second parameter
 *is true. If target process is found, it returns true without considering second parameter, else return false.
*/
static BOOLEAN Psi_SearchForSpecifiedProcessInList(PUCHAR pszProcessName, BOOLEAN bRemove,BOOLEAN bMonitor)
{
	BOOLEAN bRet = TRUE ;
	KIRQL oldIrql ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;

	try{

		TmpListEntryPtr = g_ProcessListHead.Flink ;
		while(&g_ProcessListHead != TmpListEntryPtr)
		{
			psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;

			if (!_strnicmp(psProcessInfo->szProcessName, pszProcessName, strlen(pszProcessName)))
			{
				psProcessInfo->bMonitor = bMonitor;
				DbgPrint("******** psProcessInfo->bMonitor:%u  pszProcessName is %s\n",bRet,szProcessName);
				bRet = TRUE;
				if (bRemove)
				{
					KeAcquireSpinLock(&g_ProcessListLock, &oldIrql) ;
					RemoveEntryList(&psProcessInfo->ProcessList) ;
					KeReleaseSpinLock(&g_ProcessListLock, oldIrql) ;
					ExFreePool(psProcessInfo) ;
					psProcessInfo = NULL ;
				}
				__leave ;
			}

			TmpListEntryPtr = TmpListEntryPtr->Flink ;
		}

		bRet = FALSE ;
	}
	finally{
		/**/
		//Todo some post work here
	}

	return bRet ;
}

/*
* 获取参数二提供的进程运行环境的进程名，如果没有提供参数二，那么默认获取当前进程的名称，参数一表示保存进程名称的内存首地址。
*/
PCHAR Ps_GetProcessName(PCHAR pszProcessName, PEPROCESS pEProcess)
{
	PEPROCESS curproc = pEProcess;
	char *nameptr ;

	if (g_nProcessNameOffset)
	{
		if (!curproc)
		{
			curproc = PsGetCurrentProcess() ;
		}
		nameptr = (PCHAR)curproc + g_nProcessNameOffset ;
		strncpy(pszProcessName, nameptr, 15) ;
	}
	else
	{
		strcpy(pszProcessName, "???") ;
	}

	return pszProcessName ;
}

/*
 *驱动程序的加载函数DriverEntry是运行在System进程中的．通过PsGetCurrentProcess可以获取System进程的内核EPROCESS结构的地址，
 *然后从该地址开始寻找"System"字符串．找到后，便是EPROCESS的进程名存放的偏移处．得到进程名在EPROCESS结构的偏移后，
 *以后的进程调用驱动的时候，就可以直接在该偏移处获取当前进程名．
 */
ULONG
Ps_GetProcessNameOffset(
	VOID
	)
{
	PEPROCESS curproc = NULL ;
	int i = 0 ;

	curproc = PsGetCurrentProcess() ;

	for (i=0; i<3*PAGE_SIZE; i++)
	{
		if (!strncmp("System", (PCHAR)curproc+i, strlen("System")))
		{
			return i ;
		}
	}

	return 0 ;
}
