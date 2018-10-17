/****************************************************************************/
/*                             User include                                 */
/****************************************************************************/
#include "file.h"
///#include "aes.h"
#include  "security.h"
/****************************************************************************/
/*                        Global Data definition                            */
/****************************************************************************/
PFILE_FLAG   g_psFileFlag = NULL;
INT FlagEncryptForPPT = 0;

/****************************************************************************/
/*                        Constant definition                               */
/****************************************************************************/
static UCHAR gc_sGuid[FILE_GUID_LENGTH] = { \
	                    0x3a, 0x8a, 0x2c, 0xd1, 0x50, 0xe8, 0x47, 0x5f, \
					    0xbe, 0xdb, 0xd7, 0x6c, 0xa2, 0xe9, 0x8e, 0x1d} ;


/****************************************************************************/
/*                        Routine definition                               */
/****************************************************************************/

/**
 * read file flag data from end of file
 */
NTSTATUS
File_ReadFileFlag(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__out PVOID Buffer
		)
{
	NTSTATUS status = STATUS_SUCCESS ;
	LARGE_INTEGER ByteOffset ;
	LARGE_INTEGER FileSize ;
	ULONG BytesRead = 0 ;
	
	try{

		ByteOffset.QuadPart = 0 ;
		status = File_ReadWriteFile(
			            IRP_MJ_READ, 
						FltObjects->Instance, 
						FltObjects->FileObject, 
						&ByteOffset, 
						FILE_FLAG_LENGTH, 
						Buffer, 
						&BytesRead,
						FLTFL_IO_OPERATION_NON_CACHED|FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}
	}
	finally{

	}

	return status ;
}


/**
 * write file flag data into end of file
 */
NTSTATUS
File_WriteFileFlag(
	   __in  PFLT_CALLBACK_DATA Data,
	   __in  PFLT_RELATED_OBJECTS FltObjects,
	   __in  PFILE_OBJECT FileObject,
	   __in  PSTREAM_CONTEXT pStreamCtx
	   )
{
	NTSTATUS status = STATUS_SUCCESS ;
	LARGE_INTEGER ByteOffset = {0} ;
	LARGE_INTEGER FileSize = {0} ;
	ULONG BytesWritten = 0 ;
	ULONG writelen = sizeof(FILE_FLAG) ;
	PFILE_FLAG psFileFlag = NULL ;

	try{

		File_GetFileSize(Data, FltObjects, &FileSize) ;

        //allocate local file flag buffer
		psFileFlag = (PFILE_FLAG)ExAllocatePoolWithTag(NonPagedPool, FILE_FLAG_LENGTH, FILEFLAG_POOL_TAG) ;
		if (NULL == psFileFlag)
		{
			status = STATUS_INSUFFICIENT_RESOURCES ;
			__leave ;
		}
		RtlCopyMemory(psFileFlag, g_psFileFlag, FILE_FLAG_LENGTH) ; //ʵ��������Ӧ���ǵ�ǰ�ļ������flag

        //set current file size into file flag buffer
		psFileFlag->FileValidLength= pStreamCtx->FileValidLength.QuadPart;
		FileSize.QuadPart = pStreamCtx->FileValidLength.QuadPart ;

		//calculate padded file size
		if (FileSize.QuadPart % SECTOR_SIZE)
		{//file size is not multiply of sector size
			FileSize.QuadPart = FileSize.QuadPart + (SECTOR_SIZE - FileSize.QuadPart % SECTOR_SIZE) + FILE_FLAG_LENGTH ;
		}
		else
		{//file size is multiply of sector size
			FileSize.QuadPart += FILE_FLAG_LENGTH ;
		}

		//RtlCopyMemory(psFileFlag->FileKeyHash, pStreamCtx->szKeyHash, HASH_SIZE) ;

		//write file flag into file trail
		ByteOffset.QuadPart = FileSize.QuadPart - FILE_FLAG_LENGTH ;
		status = File_ReadWriteFile(
					IRP_MJ_WRITE, 
					FltObjects->Instance, 
					FileObject, 
					&ByteOffset, 
					FILE_FLAG_LENGTH, 
					psFileFlag, 
					&BytesWritten,
					FLTFL_IO_OPERATION_NON_CACHED|FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET) ;
	}
	finally{	
		
	}

	return status ;
}

static
NTSTATUS File_ReadWriteFileComplete(
    PDEVICE_OBJECT dev,
    PIRP irp,
    PVOID context
    )
{
    *irp->UserIosb = irp->IoStatus;
    KeSetEvent(irp->UserEvent, 0, FALSE);
    IoFreeIrp(irp);
    return STATUS_MORE_PROCESSING_REQUIRED;
}


NTSTATUS
File_ReadWriteFile(
	    __in ULONG MajorFunction,
	    __in PFLT_INSTANCE Instance,
		__in PFILE_OBJECT FileObject,
		__in PLARGE_INTEGER ByteOffset,
		__in ULONG Length,
		__in PVOID  Buffer,
		__out PULONG BytesReadWrite,
		__in FLT_IO_OPERATION_FLAGS FltFlags
		)
{
	ULONG i;
    PIRP irp;
    KEVENT Event;
    PIO_STACK_LOCATION ioStackLocation;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

	PDEVICE_OBJECT pVolumeDevObj = NULL ;
	PDEVICE_OBJECT pFileSysDevObj= NULL ;
	PDEVICE_OBJECT pNextDevObj = NULL ;

	//��ȡminifilter�����²���豸����
	pVolumeDevObj = IoGetDeviceAttachmentBaseRef(FileObject->DeviceObject) ;
	if((NULL == pVolumeDevObj)||(pVolumeDevObj->Vpb== NULL))//Original if(NULL == pVolumeDevObj) avoid Bsod
	{
		return STATUS_UNSUCCESSFUL ;
	}
	pFileSysDevObj = pVolumeDevObj->Vpb->DeviceObject ;
	pNextDevObj = pFileSysDevObj ;

	if (NULL == pNextDevObj)
	{
		ObDereferenceObject(pVolumeDevObj) ;
		return STATUS_UNSUCCESSFUL ;
	}

	// Building IRP
    KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	// AllocateIrp irp.
    irp = IoAllocateIrp(pNextDevObj->StackSize, FALSE);
    if(irp == NULL) {
		ObDereferenceObject(pVolumeDevObj) ;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
  
    irp->AssociatedIrp.SystemBuffer = NULL;
    irp->MdlAddress = NULL;
    irp->UserBuffer = Buffer;
    irp->UserEvent = &Event;
    irp->UserIosb = &IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->RequestorMode = KernelMode;
	if(MajorFunction == IRP_MJ_READ)
		irp->Flags = IRP_DEFER_IO_COMPLETION|IRP_READ_OPERATION|IRP_NOCACHE;
	else if (MajorFunction == IRP_MJ_WRITE)
		irp->Flags = IRP_DEFER_IO_COMPLETION|IRP_WRITE_OPERATION|IRP_NOCACHE;
	else
	{
		ObDereferenceObject(pVolumeDevObj) ;
		return STATUS_UNSUCCESSFUL ;
	}

	if ((FltFlags & FLTFL_IO_OPERATION_PAGING) == FLTFL_IO_OPERATION_PAGING)
	{
		irp->Flags |= IRP_PAGING_IO ;
	}

	// fill irpsp
    ioStackLocation = IoGetNextIrpStackLocation(irp);
	ioStackLocation->MajorFunction = (UCHAR)MajorFunction;
    ioStackLocation->MinorFunction = (UCHAR)IRP_MN_NORMAL;
    ioStackLocation->DeviceObject = pNextDevObj;
    ioStackLocation->FileObject = FileObject ;
	if(MajorFunction == IRP_MJ_READ)
	{
		ioStackLocation->Parameters.Read.ByteOffset = *ByteOffset;
		ioStackLocation->Parameters.Read.Length = Length;
	}
	else
	{
		ioStackLocation->Parameters.Write.ByteOffset = *ByteOffset;
		ioStackLocation->Parameters.Write.Length = Length ;
	}

	// Set Completion Routine
    IoSetCompletionRoutine(irp, File_ReadWriteFileComplete, 0, TRUE, TRUE, TRUE);
    (void) IoCallDriver(pNextDevObj, irp);
    KeWaitForSingleObject(&Event, Executive, KernelMode, TRUE, 0);
	*BytesReadWrite = IoStatusBlock.Information;

	ObDereferenceObject(pVolumeDevObj) ;
    
	return IoStatusBlock.Status;
}

void Cc_ClearFileCache(PFILE_OBJECT FileObject, BOOLEAN bIsFlushCache, PLARGE_INTEGER FileOffset, ULONG Length);
/**
 * encrypt entire file manually, and at the end write file flag
 * into end of file.
 */
NTSTATUS
File_UpdateEntireFileByFileObject(//�ú��������ڳ��εĴ��������������Ѿ�˵���Ǹ��Ѿ����ܹ���PPT�ļ���
	__in PFLT_CALLBACK_DATA Data,
	__in PFLT_RELATED_OBJECTS FltObjects,
	__in PFILE_OBJECT FileObject, 
	__in PSTREAM_CONTEXT pStreamCtx,
	__in PVOLUME_CONTEXT pVolCtx
	)
{
	NTSTATUS status = STATUS_SUCCESS ;
	PUCHAR Buffer = NULL ;
	LARGE_INTEGER ReadWriteOffset = {0} ;
	BOOLEAN EndOfFile = FALSE;
	ULONG uReadBytes = 0 ;
	ULONG uWriteBytes = 0 ;
	ULONG uAllocateBufferSize = 1024*64 ; 
	ULONG uReadWriteLength = 0 ;
	ULONG uOffset = 0 ;
	LARGE_INTEGER FileSize = {0} ;
	PFILE_FLAG psFileFlag = NULL ;
	KIRQL OldIrql ;

	try{

		//�жϷ���ռ䳤���Ƿ�SectorSize����
		if ((uAllocateBufferSize % pVolCtx->SectorSize) != 0)
		{//����SectorSizeĿǰΪ512bytes������ʱ�ȷ���ʧ�ܣ��Ժ���Զ�AllocateBufferSize���е���
			status = ERR_CORE_LENGTH_NOT_ALIGNED ;
			__leave ;
		}

		Buffer = FltAllocatePoolAlignedWithTag(FltObjects->Instance,PagedPool, uAllocateBufferSize, FILEFLAG_POOL_TAG);
		if (!Buffer)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			__leave ;
		}

        //allocate local file flag buffer
		psFileFlag = (PFILE_FLAG)ExAllocatePoolWithTag(NonPagedPool, FILE_FLAG_LENGTH, FILEFLAG_POOL_TAG) ;
		if (NULL == psFileFlag)
		{
			status = STATUS_INSUFFICIENT_RESOURCES ;
			__leave ;
		}
		RtlCopyMemory(psFileFlag, g_psFileFlag, FILE_FLAG_LENGTH) ; //ʵ��������Ӧ���ǵ�ǰ�ļ������flag

        //set current file size into file flag buffer
        File_GetFileSize(Data, FltObjects, &FileSize) ;//Get File Size of current file
		psFileFlag->FileValidLength= FileSize.QuadPart ;

		//calculate padded file size
		if (FileSize.QuadPart % SECTOR_SIZE)
		{//file size is not multiply of sector size ���е�multiply������������˼����~
			//FileSize.QuadPart�а�����һ�������е���������(SECTOR_SIZE - FileSize.QuadPart % SECTOR_SIZE)�Ǽ����512��ȥ������һ��ɾ����ʣ�������� ���� + һ��ɾ����ʣ���� = 512 
			FileSize.QuadPart = FileSize.QuadPart + (SECTOR_SIZE - FileSize.QuadPart % SECTOR_SIZE) + FILE_FLAG_LENGTH ;//����SECTOR_SIZE - FileSize.QuadPart % SECTOR_SIZE��ͱ��512���������ˣ���Ϊ����������512��ȥ������ֵ��
		}
		else
		{//file size is multiply of sector size
			FileSize.QuadPart += FILE_FLAG_LENGTH ;
		}
		//RtlCopyMemory(psFileFlag->FileKeyHash, pStreamCtx->szKeyHash, HASH_SIZE) ;
		

		while (TRUE)
		{
			status = File_ReadWriteFile(IRP_MJ_READ, 
										FltObjects->Instance, 
										FileObject, 
										&ReadWriteOffset,
										uAllocateBufferSize, //ÿ�������� PPT �ļ�����ô������ ��1024*64
										Buffer, 
										&uReadBytes,//ʵ�ʶ����Ĵ�С
										FLTFL_IO_OPERATION_NON_CACHED|FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET) ;
			if (!NT_SUCCESS(status))
				break;

			if (0 == uReadBytes)
				break;

			if (KeGetCurrentIrql() > PASSIVE_LEVEL)
				ExAcquireSpinLock(&pVolCtx->FsCryptSpinLock, &OldIrql);
			else
				ExAcquireFastMutex(&pVolCtx->FsCtxTableMutex) ;

			
			//Start  ������Ҫѭ�����ܵĴ��� & Ӧ����������ɶ�PPT�����Ļ������Ĵ�������� File_ReadWriteFile δ��ȡ���������� Important !

					
						//data_decrypt(Buffer, uReadBytes);
					
			//End
			if (data_encrypt(Buffer, uReadBytes))
			{
				//data_encrypt(Buffer, uReadBytes);

				FlagEncryptForPPT = 0;
				//����ʧ��
				DbgPrint("---------------------data_encrypt Failed For ppt----------------\n");
				if (KeGetCurrentIrql() > PASSIVE_LEVEL)
					ExReleaseSpinLock(&pVolCtx->FsCryptSpinLock, OldIrql) ;
				else
					ExReleaseFastMutex(&pVolCtx->FsCtxTableMutex) ;
			  break ;
			}
			
			if (KeGetCurrentIrql() > PASSIVE_LEVEL)
				ExReleaseSpinLock(&pVolCtx->FsCryptSpinLock, OldIrql) ;
			else
				ExReleaseFastMutex(&pVolCtx->FsCtxTableMutex) ;

			if (uReadBytes < uAllocateBufferSize)
				EndOfFile = TRUE;

			status = File_ReadWriteFile(IRP_MJ_WRITE, //���ܺ���д���ļ�
										FltObjects->Instance, 
										FileObject, 
										&ReadWriteOffset,
										uReadBytes, 
										Buffer, 
										&uWriteBytes,
										FLTFL_IO_OPERATION_NON_CACHED|FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET) ;
			if (!NT_SUCCESS(status))
				break;

			if (EndOfFile)
				break;

			

			//�޸�ƫ���� Ϊ��ѭ���е��ٴζ�ȡ���ٴμ���
			uOffset += uAllocateBufferSize ;
			ReadWriteOffset.QuadPart += uAllocateBufferSize ;

			//��ջ�����
			RtlZeroMemory(Buffer, uAllocateBufferSize) ;
		}

		// write file flag
		ReadWriteOffset.QuadPart = FileSize.QuadPart - FILE_FLAG_LENGTH ;
		File_ReadWriteFile(IRP_MJ_WRITE, 
						   FltObjects->Instance, 
						   FileObject, 
						   &ReadWriteOffset, 
						   FILE_FLAG_LENGTH, 
						   psFileFlag, 
						   &uWriteBytes,
						   FLTFL_IO_OPERATION_NON_CACHED|FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET) ;
		DbgPrint("--------------------- write file flag For ppt and Finished !!!!! ---------------------\n");

		//Cc_ClearFileCache(FileObject, TRUE, NULL, 0) ; 
		
	}
	finally{

		if (Buffer)
		{
			FltFreePoolAlignedWithTag(FltObjects->Instance, Buffer, FILEFLAG_POOL_TAG);
			Buffer = NULL ;
		}

		if (psFileFlag)
		{
			ExFreePoolWithTag(psFileFlag, FILEFLAG_POOL_TAG) ;
			psFileFlag = NULL ;
		}
	}

	return status;
}


//
NTSTATUS 
File_GetFileOffset(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__out PLARGE_INTEGER FileOffset
	)
{
	NTSTATUS status;
	FILE_POSITION_INFORMATION NewPos;	

	//
	status = FltQueryInformationFile(FltObjects->Instance,
									 FltObjects->FileObject,
									 &NewPos,
									 sizeof(FILE_POSITION_INFORMATION),
									 FilePositionInformation,
									 NULL
									 ) ;
	if(NT_SUCCESS(status))
	{
		FileOffset->QuadPart = NewPos.CurrentByteOffset.QuadPart;
	}

	return status;
}


//
NTSTATUS File_SetFileOffset(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__in PLARGE_INTEGER FileOffset
	)
{
	NTSTATUS status;
	FILE_POSITION_INFORMATION NewPos;
	//
	LARGE_INTEGER NewOffset = {0};

	NewOffset.QuadPart = FileOffset->QuadPart;
	NewOffset.LowPart = FileOffset->LowPart;

	NewPos.CurrentByteOffset = NewOffset;

	status = FltSetInformationFile(FltObjects->Instance,
								   FltObjects->FileObject,
								   &NewPos,
								   sizeof(FILE_POSITION_INFORMATION),
								   FilePositionInformation
								   ) ;
	return status;
}


NTSTATUS 
File_SetFileSize(
    __in PFLT_CALLBACK_DATA Data,
	__in PFLT_RELATED_OBJECTS FltObjects,
	__in PLARGE_INTEGER FileSize
	)
{
	NTSTATUS status = STATUS_SUCCESS ;
	FILE_END_OF_FILE_INFORMATION EndOfFile;
	PFSRTL_COMMON_FCB_HEADER Fcb = (PFSRTL_COMMON_FCB_HEADER)FltObjects->FileObject->FsContext ;;

	EndOfFile.EndOfFile.QuadPart = FileSize->QuadPart;
	EndOfFile.EndOfFile.LowPart = FileSize->LowPart;

	//
	status = FltSetInformationFile(FltObjects->Instance,
		FltObjects->FileObject,
		&EndOfFile,
		sizeof(FILE_END_OF_FILE_INFORMATION),
		FileEndOfFileInformation
		) ;

	return status;	
}


/**
 * Get file size, returned size is summation of  
 * file data length, padding length and file flag length
 */
NTSTATUS 
File_GetFileSize(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__in PLARGE_INTEGER FileSize
	)
{
	NTSTATUS status;
	FILE_STANDARD_INFORMATION fileInfo ;

	//
	status = FltQueryInformationFile(FltObjects->Instance,
									 FltObjects->FileObject,
									 &fileInfo,
									 sizeof(FILE_STANDARD_INFORMATION),
									 FileStandardInformation,
									 NULL
									 ) ;
	if (NT_SUCCESS(status))
	{
		FileSize->QuadPart = fileInfo.EndOfFile.QuadPart ;
	}
	else
	{
		FileSize->QuadPart = 0 ;
	}

	return status;
}


/**
 * Get file information
 */
NTSTATUS 
File_GetFileStandardInfo(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__in PLARGE_INTEGER FileAllocationSize,
	__in PLARGE_INTEGER FileSize,
	__in PBOOLEAN bDirectory
	)
{
	NTSTATUS status = STATUS_SUCCESS ;
	FILE_STANDARD_INFORMATION sFileStandardInfo ;

	//
	status = FltQueryInformationFile(FltObjects->Instance,
									 FltObjects->FileObject,
									 &sFileStandardInfo,
									 sizeof(FILE_STANDARD_INFORMATION),
									 FileStandardInformation,
									 NULL
									 ) ;
	if (NT_SUCCESS(status))
	{
		if (NULL != FileSize)
			*FileSize = sFileStandardInfo.EndOfFile ;
		if (NULL != FileAllocationSize)
			*FileAllocationSize = sFileStandardInfo.AllocationSize ;
		if (NULL != bDirectory)
			*bDirectory = sFileStandardInfo.Directory ;
	}

	return status ;
}


/**
 * allocate memory for global file flag information,
 * init global file flag and fill GUID in it.
 */
NTSTATUS
File_InitFileFlag()
{
	if (NULL != g_psFileFlag)
		return STATUS_SUCCESS ;

	g_psFileFlag = ExAllocatePoolWithTag(NonPagedPool, FILE_FLAG_LENGTH, FILEFLAG_POOL_TAG) ;
	if (NULL == g_psFileFlag)
	{
		return STATUS_INSUFFICIENT_RESOURCES ;
	}
	RtlZeroMemory(g_psFileFlag, FILE_FLAG_LENGTH) ;

	// initialize FileFlagHeader with gc_sGuid
	RtlCopyMemory(g_psFileFlag->FileFlagHeader, gc_sGuid, FILE_GUID_LENGTH) ;

	return STATUS_SUCCESS ;
}


/**
 * deallocate memory occupied by global file flag,
 * when engine is unloaded.
 */
NTSTATUS
File_UninitFileFlag()
{
	if (NULL != g_psFileFlag)
	{
		ExFreePoolWithTag(g_psFileFlag, FILEFLAG_POOL_TAG) ;
		g_psFileFlag = NULL ;
	}

	return STATUS_SUCCESS ;
}
