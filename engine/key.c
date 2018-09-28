#include "key.h"
#include "..\include\iocommon.h"

PKEYLIST_INFO g_psKeyListInfo = NULL ;


//本函数利用参数来初始化key列表
BOOLEAN
Key_InitKeyList(
__in	PVOID InputBuffer
	)
{
	BOOLEAN bRet = TRUE ;
	ULONG uIndex = 0 ;
	PMSG_SEND_SET_HISKEY_INFO psSendSetHisKeyInfo = (PMSG_SEND_SET_HISKEY_INFO)InputBuffer ;
	ULONG uTotalCount = psSendSetHisKeyInfo->sKeyListInfo.uItemCount ;

	try{
		if (NULL == g_psKeyListInfo)
		{
			g_psKeyListInfo = (PKEYLIST_INFO)ExAllocatePoolWithTag(NonPagedPool, 
				                                        sizeof(ULONG) + uTotalCount*sizeof(FILEKEY_INFO), 
														KEY_POOL_TAG) ;
			if (NULL == g_psKeyListInfo)
			{
				bRet = FALSE ;
				__leave ;
			}
			g_psKeyListInfo->uItemCount = uTotalCount ;
		}
		
		RtlCopyMemory(g_psKeyListInfo, &psSendSetHisKeyInfo->sKeyListInfo, sizeof(ULONG) + uTotalCount*sizeof(FILEKEY_INFO)) ;

	}
	finally{
	}

	return bRet ;
}

BOOLEAN
Key_GetKeyByDigest(
__in	UCHAR* pszFileKeyHash,
__in	ULONG  uHashSize,
__in	UCHAR* pszFileKey,
__in	ULONG  uKeyLength
	)
{
	BOOLEAN bRet = TRUE ;
	ULONG uIndex = 0 ;
	UCHAR szIV[16] = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6} ;

	extern UCHAR g_szCurFileKey[MAX_KEY_LENGTH] ;

	ASSERT(uHashSize <= HASH_SIZE) ;
	ASSERT(uKeyLength <= MAX_KEY_LENGTH) ;

	if (NULL == g_psKeyListInfo)
	{
		return FALSE ;
	}

	//循环查找列表
	while (uIndex < g_psKeyListInfo->uItemCount)
	{
		//找到了对应的hash码
		if (uHashSize == RtlCompareMemory(pszFileKeyHash, g_psKeyListInfo->sFileKeyInfo[uIndex].szCurKeyHash, uHashSize))
		{
			//使用CBC模式加密
			///COUNTER_MODE_CONTEXT* aesctx = counter_mode_ctx_init(szIV, g_szCurFileKey, MAX_KEY_LENGTH) ;
			///memcpy(pszFileKey, g_psKeyListInfo->sFileKeyInfo[uIndex].szCurKeyCipher, uKeyLength) ;
			///data_crypt(aesctx, pszFileKey, 0, uKeyLength) ;
			///counter_mode_ctx_destroy(aesctx) ;

			return bRet ;
		}

		uIndex ++ ;
	}
	
	return FALSE ;
}

BOOLEAN
Key_DestroyKeyList(
	)
{
	if (NULL != g_psKeyListInfo)
		ExFreePoolWithTag(g_psKeyListInfo, KEY_POOL_TAG) ;
	g_psKeyListInfo = NULL;
}