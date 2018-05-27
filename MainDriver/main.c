#include <ntddk.h>
#include <ntdddisk.h>
#include <scsi.h>
#include <ntddscsi.h>
#include <mountdev.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdf.h>
#include <ntdef.h>
#include <mountmgr.h>
#include <stdio.h>
#include "class2.h"
#include "hooks.h"

UNICODE_STRING DriverRegistryPath;

PDRIVER_DISPATCH RealDiskDeviceControl = NULL;
PDRIVER_OBJECT DiskDriver = NULL;

#define MAX_HD_COUNT    10
#define SN_LEN          20

typedef struct _SerialNumbers
{
	UCHAR DiskSerial[SN_LEN];
	UCHAR ChangeTo[SN_LEN];
}SerialNumbers, *PSerialNumbers;

typedef struct _SNInfo
{
	ULONG Count;
	SerialNumbers SNS[MAX_HD_COUNT];
}SNInfo, *PSNInfo;


extern NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
	IN PUNICODE_STRING ObjectName,
	IN ULONG Attributes,
	IN PACCESS_STATE PassedAccessState,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_TYPE ObjectType,
	IN KPROCESSOR_MODE AccessMode,
	IN OUT PVOID ParseContext,
	OUT PVOID * Object
);

extern POBJECT_TYPE *IoDriverObjectType;

#define SMART_RCV_DRIVE_DATA \
  CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define  DFP_SEND_DRIVE_COMMAND   \
  CTL_CODE(IOCTL_DISK_BASE, 0x0021, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define  DFP_RECEIVE_DRIVE_DATA   \
  CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)


#define  IDE_ATA_IDENTIFY           0xEC

typedef struct _IDINFO
{
	USHORT  wGenConfig;     // WORD 0: ������Ϣ��
	USHORT  wNumCyls;     // WORD 1: ������
	USHORT  wReserved2;     // WORD 2: ����
	USHORT  wNumHeads;     // WORD 3: ��ͷ��
	USHORT  wReserved4;        // WORD 4: ����
	USHORT  wReserved5;        // WORD 5: ����
	USHORT  wNumSectorsPerTrack;  // WORD 6: ÿ�ŵ�������
	USHORT  wVendorUnique[3];   // WORD 7-9: �����趨ֵ
	CHAR    sSerialNumber[20];   // WORD 10-19:���к�
	USHORT  wBufferType;    // WORD 20: ��������
	USHORT  wBufferSize;    // WORD 21: �����С
	USHORT  wECCSize;     // WORD 22: ECCУ���С
	CHAR    sFirmwareRev[8];   // WORD 23-26: �̼��汾
	CHAR    sModelNumber[40];   // WORD 27-46: �ڲ��ͺ�
	USHORT  wMoreVendorUnique;   // WORD 47: �����趨ֵ
	USHORT  wReserved48;    // WORD 48: ����
	struct {
		USHORT  reserved1 : 8;
		USHORT  DMA : 1;     // 1=֧��DMA
		USHORT  LBA : 1;     // 1=֧��LBA
		USHORT  DisIORDY : 1;    // 1=�ɲ�ʹ��IORDY
		USHORT  IORDY : 1;    // 1=֧��IORDY
		USHORT  SoftReset : 1;   // 1=��ҪATA������
		USHORT  Overlap : 1;    // 1=֧���ص�����
		USHORT  Queue : 1;    // 1=֧���������
		USHORT  InlDMA : 1;    // 1=֧�ֽ����ȡDMA
	} wCapabilities;     // WORD 49: һ������
	USHORT  wReserved1;     // WORD 50: ����
	USHORT  wPIOTiming;     // WORD 51: PIOʱ��
	USHORT  wDMATiming;     // WORD 52: DMAʱ��
	struct {
		USHORT  CHSNumber : 1;   // 1=WORD 54-58��Ч
		USHORT  CycleNumber : 1;   // 1=WORD 64-70��Ч
		USHORT  UnltraDMA : 1;   // 1=WORD 88��Ч
		USHORT  reserved : 13;
	} wFieldValidity;     // WORD 53: �����ֶ���Ч�Ա�־
	USHORT  wNumCurCyls;    // WORD 54: CHS��Ѱַ��������
	USHORT  wNumCurHeads;    // WORD 55: CHS��Ѱַ�Ĵ�ͷ��
	USHORT  wNumCurSectorsPerTrack;  // WORD 56: CHS��Ѱַÿ�ŵ�������
	USHORT  wCurSectorsLow;    // WORD 57: CHS��Ѱַ����������λ��
	USHORT  wCurSectorsHigh;   // WORD 58: CHS��Ѱַ����������λ��
	struct {
		USHORT  CurNumber : 8;   // ��ǰһ���Կɶ�д������
		USHORT  Multi : 1;    // 1=��ѡ���������д
		USHORT  reserved1 : 7;
	} wMultSectorStuff;     // WORD 59: ��������д�趨
	ULONG  dwTotalSectors;    // WORD 60-61: LBA��Ѱַ��������
	USHORT  wSingleWordDMA;    // WORD 62: ���ֽ�DMA֧������
	struct {
		USHORT  Mode0 : 1;    // 1=֧��ģʽ0 (4.17Mb/s)
		USHORT  Mode1 : 1;    // 1=֧��ģʽ1 (13.3Mb/s)
		USHORT  Mode2 : 1;    // 1=֧��ģʽ2 (16.7Mb/s)
		USHORT  Reserved1 : 5;
		USHORT  Mode0Sel : 1;    // 1=��ѡ��ģʽ0
		USHORT  Mode1Sel : 1;    // 1=��ѡ��ģʽ1
		USHORT  Mode2Sel : 1;    // 1=��ѡ��ģʽ2
		USHORT  Reserved2 : 5;
	} wMultiWordDMA;     // WORD 63: ���ֽ�DMA֧������
	struct {
		USHORT  AdvPOIModes : 8;   // ֧�ָ߼�POIģʽ��
		USHORT  reserved : 8;
	} wPIOCapacity;      // WORD 64: �߼�PIO֧������
	USHORT  wMinMultiWordDMACycle;  // WORD 65: ���ֽ�DMA�������ڵ���Сֵ
	USHORT  wRecMultiWordDMACycle;  // WORD 66: ���ֽ�DMA�������ڵĽ���ֵ
	USHORT  wMinPIONoFlowCycle;   // WORD 67: ��������ʱPIO�������ڵ���Сֵ
	USHORT  wMinPOIFlowCycle;   // WORD 68: ��������ʱPIO�������ڵ���Сֵ
	USHORT  wReserved69[11];   // WORD 69-79: ����
	struct {
		USHORT  Reserved1 : 1;
		USHORT  ATA1 : 1;     // 1=֧��ATA-1
		USHORT  ATA2 : 1;     // 1=֧��ATA-2
		USHORT  ATA3 : 1;     // 1=֧��ATA-3
		USHORT  ATA4 : 1;     // 1=֧��ATA/ATAPI-4
		USHORT  ATA5 : 1;     // 1=֧��ATA/ATAPI-5
		USHORT  ATA6 : 1;     // 1=֧��ATA/ATAPI-6
		USHORT  ATA7 : 1;     // 1=֧��ATA/ATAPI-7
		USHORT  ATA8 : 1;     // 1=֧��ATA/ATAPI-8
		USHORT  ATA9 : 1;     // 1=֧��ATA/ATAPI-9
		USHORT  ATA10 : 1;    // 1=֧��ATA/ATAPI-10
		USHORT  ATA11 : 1;    // 1=֧��ATA/ATAPI-11
		USHORT  ATA12 : 1;    // 1=֧��ATA/ATAPI-12
		USHORT  ATA13 : 1;    // 1=֧��ATA/ATAPI-13
		USHORT  ATA14 : 1;    // 1=֧��ATA/ATAPI-14
		USHORT  Reserved2 : 1;
	} wMajorVersion;     // WORD 80: ���汾
	USHORT  wMinorVersion;    // WORD 81: ���汾
	USHORT  wReserved82[6];    // WORD 82-87: ����
	struct {
		USHORT  Mode0 : 1;    // 1=֧��ģʽ0 (16.7Mb/s)
		USHORT  Mode1 : 1;    // 1=֧��ģʽ1 (25Mb/s)
		USHORT  Mode2 : 1;    // 1=֧��ģʽ2 (33Mb/s)
		USHORT  Mode3 : 1;    // 1=֧��ģʽ3 (44Mb/s)
		USHORT  Mode4 : 1;    // 1=֧��ģʽ4 (66Mb/s)
		USHORT  Mode5 : 1;    // 1=֧��ģʽ5 (100Mb/s)
		USHORT  Mode6 : 1;    // 1=֧��ģʽ6 (133Mb/s)
		USHORT  Mode7 : 1;    // 1=֧��ģʽ7 (166Mb/s) ???
		USHORT  Mode0Sel : 1;    // 1=��ѡ��ģʽ0
		USHORT  Mode1Sel : 1;    // 1=��ѡ��ģʽ1
		USHORT  Mode2Sel : 1;    // 1=��ѡ��ģʽ2
		USHORT  Mode3Sel : 1;    // 1=��ѡ��ģʽ3
		USHORT  Mode4Sel : 1;    // 1=��ѡ��ģʽ4
		USHORT  Mode5Sel : 1;    // 1=��ѡ��ģʽ5
		USHORT  Mode6Sel : 1;    // 1=��ѡ��ģʽ6
		USHORT  Mode7Sel : 1;    // 1=��ѡ��ģʽ7
	} wUltraDMA;      // WORD 88:  Ultra DMA֧������
	USHORT    wReserved89[167];   // WORD 89-255
} IDINFO, *PIDINFO;

char Hex(WCHAR wch)
{
	if (wch <= '9' && wch >= '0') {
		return wch - '0';
	}

	if (wch <= 'F' && wch >= 'A') {
		return wch - 'A' + 0xA;
	}

	if (wch <= 'f' && wch >= 'a') {
		return wch - 'a' + 0xa;
	}
	return 0;
}

VOID ToHexStr(UCHAR* bytes, ULONG len, WCHAR* buf)
{
	ULONG i = 0;
	UCHAR m, n;
	for (i = 0; i < len; ++i) {
		m = bytes[i] / 0x10;
		n = bytes[i] % 0x10;
		buf[i * 2] = m > 9 ? ('A' + m - 0xa) : ('0' + m);
		buf[i * 2 + 1] = n > 9 ? ('A' + n - 0xa) : ('0' + n);
	}
}

ULONG GetIndex(SNInfo* sns, UCHAR* sn)
{
	ULONG i;
	for (i = 0; i < sns->Count; ++i)
	{
		if (memcmp(sns->SNS[i].DiskSerial, sn, SN_LEN) == 0) {
			return i;
		}
	}
	return -1;
}

BOOLEAN GetSNInfo(SNInfo* info)
{
	OBJECT_ATTRIBUTES attr;
	ULONG result;
	HANDLE hReg = NULL;
	NTSTATUS status;
	PKEY_VALUE_PARTIAL_INFORMATION pvpi = NULL;
	ULONG i = 0, j = 0;
	UNICODE_STRING valueStr;
	WCHAR valueBuf[4];
	ULONG ulSize;
	PWCHAR wptr;

	InitializeObjectAttributes(&attr, &DriverRegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&hReg, KEY_QUERY_VALUE, &attr);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	do
	{
		valueBuf[0] = 's';
		valueBuf[1] = 'n';
		valueBuf[2] = '0';
		valueBuf[3] = '\0';
		RtlInitUnicodeString(&valueStr, valueBuf);

		for (i = 0; i < MAX_HD_COUNT; ++i)
		{
			valueBuf[2] = '0' + (WCHAR)i;
			status = ZwQueryValueKey(hReg, &valueStr, KeyValuePartialInformation, NULL, 0, &ulSize);
			if (STATUS_OBJECT_NAME_NOT_FOUND == status || ulSize == 0) {
				break;
			}
			pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(NonPagedPool, ulSize);
			status = ZwQueryValueKey(hReg, &valueStr, KeyValuePartialInformation, pvpi, ulSize, &result);
			if (!NT_SUCCESS(status)) {
				ExFreePool(pvpi);
				break;
			}
			if (pvpi->DataLength != 164) {
				ExFreePool(pvpi);
				break;
			}
			wptr = (PWCHAR)pvpi->Data;
			for (j = 0; j < 20; ++j)
			{
				info->SNS[i].DiskSerial[j] = Hex(wptr[j * 2]) * 0x10 + Hex(wptr[j * 2 + 1]);
				info->SNS[i].ChangeTo[j] = Hex(wptr[(20 * 2 + 1) + j * 2]) * 0x10 + Hex(wptr[(20 * 2 + 1) + j * 2 + 1]);
			}
			ExFreePool(pvpi);
		}
		info->Count = i;

	} while (0);

	if (hReg) {
		ZwClose(hReg);
	}
	return TRUE;
}

NTSTATUS HookedDiskDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION     irpStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG                  ctrlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	NTSTATUS               status;
	ULONG                  i = 0, j = 0;
	IDINFO*                info = NULL;

	PSENDCMDINPARAMS cmdInParameters = ((PSENDCMDINPARAMS)Irp->AssociatedIrp.SystemBuffer);
	ULONG            controlCode = 0;
	PSRB_IO_CONTROL  srbControl;
	ULONG_PTR        buffer;
	PDEVICE_EXTENSION      deviceExtension = DeviceObject->DeviceExtension;
	PCDB                   cdb;
	KEVENT                 event;
	IO_STATUS_BLOCK        ioStatus;
	ULONG                  length;
	PIRP                   irp2;
	SNInfo                 snInfo;


	if (ctrlCode != SMART_RCV_DRIVE_DATA) {
		return RealDiskDeviceControl(DeviceObject, Irp);
	}

	// ���µĴ��붼��������reactos/drivers/storage/class/disk.c
	do
	{
		if (irpStack->Parameters.DeviceIoControl.InputBufferLength <
			(sizeof(SENDCMDINPARAMS) - 1)) {
			status = STATUS_INVALID_PARAMETER;
			break;

		}
		else if (irpStack->Parameters.DeviceIoControl.OutputBufferLength <
			(sizeof(SENDCMDOUTPARAMS) + 512 - 1)) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		//
		// Create notification event object to be used to signal the
		// request completion.
		//

		KeInitializeEvent(&event, NotificationEvent, FALSE);

		if (cmdInParameters->irDriveRegs.bCommandReg == ID_CMD) {

			length = IDENTIFY_BUFFER_SIZE + sizeof(SENDCMDOUTPARAMS);
			controlCode = IOCTL_SCSI_MINIPORT_IDENTIFY;

		}
		else if (cmdInParameters->irDriveRegs.bCommandReg == SMART_CMD) {
			switch (cmdInParameters->irDriveRegs.bFeaturesReg) {
			case READ_ATTRIBUTES:
				controlCode = IOCTL_SCSI_MINIPORT_READ_SMART_ATTRIBS;
				length = READ_ATTRIBUTE_BUFFER_SIZE + sizeof(SENDCMDOUTPARAMS);
				break;
			case READ_THRESHOLDS:
				controlCode = IOCTL_SCSI_MINIPORT_READ_SMART_THRESHOLDS;
				length = READ_THRESHOLD_BUFFER_SIZE + sizeof(SENDCMDOUTPARAMS);
				break;
			default:
				status = STATUS_INVALID_PARAMETER;
				break;
			}
		}
		else {

			status = STATUS_INVALID_PARAMETER;
		}

		if (controlCode == 0) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		srbControl = ExAllocatePool(NonPagedPool,
			sizeof(SRB_IO_CONTROL) + length);

		if (!srbControl) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		//
		// fill in srbControl fields
		//

		srbControl->HeaderLength = sizeof(SRB_IO_CONTROL);
		RtlMoveMemory(srbControl->Signature, "SCSIDISK", 8);
		srbControl->Timeout = deviceExtension->TimeOutValue;
		srbControl->Length = length;
		srbControl->ControlCode = controlCode;

		//
		// Point to the 'buffer' portion of the SRB_CONTROL
		//

		buffer = (ULONG_PTR)srbControl + srbControl->HeaderLength;

		//
		// Ensure correct target is set in the cmd parameters.
		//

		cmdInParameters->bDriveNumber = deviceExtension->TargetId;

		//
		// Copy the IOCTL parameters to the srb control buffer area.
		//

		RtlMoveMemory((PVOID)buffer, Irp->AssociatedIrp.SystemBuffer, sizeof(SENDCMDINPARAMS) - 1);

		irp2 = IoBuildDeviceIoControlRequest(IOCTL_SCSI_MINIPORT,
			deviceExtension->PortDeviceObject,
			srbControl,
			sizeof(SRB_IO_CONTROL) + sizeof(SENDCMDINPARAMS) - 1,
			srbControl,
			sizeof(SRB_IO_CONTROL) + length,
			FALSE,
			&event,
			&ioStatus);

		if (irp2 == NULL) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		//
		// Call the port driver with the request and wait for it to complete.
		//

		status = IoCallDriver(deviceExtension->PortDeviceObject, irp2);

		if (status == STATUS_PENDING) {
			KeWaitForSingleObject(&event, Suspended, KernelMode, FALSE, NULL);
			status = ioStatus.Status;
		}

		//
		// If successful, copy the data received into the output buffer
		//

		buffer = (ULONG_PTR)srbControl + srbControl->HeaderLength;

		if (NT_SUCCESS(status)) {

			RtlMoveMemory(Irp->AssociatedIrp.SystemBuffer, (PVOID)buffer, length - 1);
			Irp->IoStatus.Information = length - 1;

			info = (IDINFO*)((SENDCMDOUTPARAMS*)Irp->AssociatedIrp.SystemBuffer)->bBuffer;
			snInfo.Count = 0;
			GetSNInfo(&snInfo);
			for (i = 0; i < snInfo.Count; ++i)
			{
				if (memcmp(info->sSerialNumber, snInfo.SNS[i].DiskSerial, 20) == 0) {
					memcpy(info->sSerialNumber, snInfo.SNS[i].ChangeTo, 20);
					break;
				}
			}
		}
		else {

			RtlMoveMemory(Irp->AssociatedIrp.SystemBuffer, (PVOID)buffer, (sizeof(SENDCMDOUTPARAMS) - 1));
			Irp->IoStatus.Information = sizeof(SENDCMDOUTPARAMS) - 1;

		}

		ExFreePool(srbControl);
	} while (0);

	Irp->IoStatus.Status = status;

	if (!NT_SUCCESS(status) && IoIsErrorUserInduced(status)) {

		IoSetHardErrorOrVerifyDevice(Irp, DeviceObject);
	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return(status);

}

BOOLEAN HookDiskDriver()
{
	UNICODE_STRING driverName;
	BOOLEAN ret = FALSE;
	NTSTATUS status;

	RtlInitUnicodeString(&driverName, L"\\driver\\disk");

	status = ObReferenceObjectByName(
		&driverName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID *)&DiskDriver);

	do
	{
		if (DiskDriver == NULL) {
			break;
		}

		RealDiskDeviceControl = DiskDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		InterlockedExchangePointer((volatile PVOID *)&DiskDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL], HookedDiskDeviceControl);
		ret = TRUE;
	} while (0);

	return ret;
}

BOOLEAN GetDiskSN(PDEVICE_OBJECT deviceObject, UCHAR* sn)
{
	NTSTATUS                status;
	PSENDCMDINPARAMS        pSCIP;
	PSENDCMDOUTPARAMS       pSCOP;
	PIRP                    Irp;
	IO_STATUS_BLOCK         ioStatus;
	KEVENT                  event;
	BOOLEAN                 ret = FALSE;

	pSCIP = (PSENDCMDINPARAMS)ExAllocatePool(NonPagedPool, sizeof(SENDCMDINPARAMS) - 1);
	pSCOP = (PSENDCMDOUTPARAMS)ExAllocatePool(NonPagedPool, sizeof(SENDCMDOUTPARAMS) + sizeof(IDINFO) - 1);

	if (pSCIP && pSCOP)
	{
		KeInitializeEvent(&event, NotificationEvent, FALSE);
		RtlZeroMemory(pSCIP, sizeof(SENDCMDINPARAMS) - 1);
		RtlZeroMemory(pSCOP, sizeof(SENDCMDOUTPARAMS) + sizeof(IDINFO) - 1);

		pSCIP->irDriveRegs.bCommandReg = IDE_ATA_IDENTIFY;
		pSCIP->cBufferSize = 0;
		pSCOP->cBufferSize = sizeof(IDINFO);

		if (Irp = IoBuildDeviceIoControlRequest(DFP_RECEIVE_DRIVE_DATA/*IRP_MJ_DEVICE_CONTROL*/, deviceObject, pSCIP, sizeof(SENDCMDINPARAMS) - 1,
			pSCOP, sizeof(SENDCMDOUTPARAMS) + sizeof(IDINFO) - 1, FALSE, &event, &ioStatus)) {
			status = IoCallDriver(deviceObject, Irp);
			if (status == STATUS_PENDING) {
				KeWaitForSingleObject(&event, Suspended, KernelMode, FALSE, NULL);
				status = ioStatus.Status;
			}
			if (NT_SUCCESS(status)) {
				PIDINFO pinfo = (PIDINFO)pSCOP->bBuffer;
				memcpy(sn, pinfo->sSerialNumber, sizeof(pinfo->sSerialNumber));
				ret = TRUE;
			}
			else {
			}
		}
	}
	if (pSCOP)
		ExFreePool(pSCOP);
	if (pSCIP)
		ExFreePool(pSCIP);

	return ret;
}


BOOLEAN SetOriginSNInfo()
{
	BOOLEAN ret = FALSE;
	NTSTATUS status;
	UNICODE_STRING driverName;
	PDEVICE_OBJECT deviceObject;
	PDRIVER_OBJECT driverObject;
	SNInfo sns;
	ULONG index = 0;
	OBJECT_ATTRIBUTES attr;
	ULONG result;
	HANDLE hReg = NULL;
	PKEY_VALUE_PARTIAL_INFORMATION pvpi = NULL;
	UNICODE_STRING valueStr;
	WCHAR valueBuf[4];
	WCHAR tmpBuf[82];
	ULONG ulSize;
	PWCHAR wptr;
	ULONG i = 0, j = 0;
	SNInfo oldInfo;
	BOOLEAN found = FALSE;


	sns.Count = 0;
	oldInfo.Count = 0;
	RtlInitUnicodeString(&driverName, L"\\driver\\disk");

	do
	{
		status = ObReferenceObjectByName(
			&driverName,
			OBJ_CASE_INSENSITIVE,
			NULL,
			0,
			*IoDriverObjectType,
			KernelMode,
			NULL,
			(PVOID *)&driverObject);
		if (driverObject == NULL) {
			break;
		}

		deviceObject = driverObject->DeviceObject;
		while (deviceObject) {
			if (GetDiskSN(deviceObject, sns.SNS[index].DiskSerial)) {
				if (GetIndex(&sns, sns.SNS[index].DiskSerial) == -1) {
					index++;
					sns.Count = index;
				}
			}
			deviceObject = deviceObject->NextDevice;
		}

		ObDereferenceObject(driverObject);

		GetSNInfo(&oldInfo);

		for (i = 0; i < index; ++i)
		{
			found = FALSE;
			for (j = 0; j < oldInfo.Count; ++j)
			{
				if (memcmp(oldInfo.SNS[j].DiskSerial, sns.SNS[i].DiskSerial, 20) == 0) {
					memcpy(sns.SNS[i].ChangeTo, oldInfo.SNS[j].ChangeTo, 20);
					found = TRUE;
					break;
				}
			}
			if (!found) {
				memcpy(sns.SNS[i].ChangeTo, sns.SNS[i].DiskSerial, 20);
			}
		}

		InitializeObjectAttributes(&attr, &DriverRegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = ZwOpenKey(&hReg, KEY_WRITE, &attr);
		if (!NT_SUCCESS(status)) {
			break;
		}

		valueBuf[0] = 's';
		valueBuf[1] = 'n';
		valueBuf[2] = '0';
		valueBuf[3] = '\0';
		RtlInitUnicodeString(&valueStr, valueBuf);

		for (i = 0; i < index; ++i)
		{
			wptr = tmpBuf;
			ToHexStr(sns.SNS[i].DiskSerial, SN_LEN, wptr);
			wptr += (SN_LEN * 2);
			*wptr++ = '|';
			ToHexStr(sns.SNS[i].ChangeTo, SN_LEN, wptr);
			wptr += (SN_LEN * 2);
			*wptr = 0;

			valueBuf[2] = '0' + (WCHAR)i;
			status = ZwSetValueKey(hReg, &valueStr, 0, REG_SZ, tmpBuf, (SN_LEN * 4 + 2) * sizeof(WCHAR));
			if (!NT_SUCCESS(status)) {
				continue;
			}
		}
		ZwClose(hReg);
		ret = TRUE;
	} while (0);

	return ret;
}

VOID UnhookDiskDriver()
{
	InterlockedExchangePointer((volatile PVOID *)&DiskDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL], RealDiskDeviceControl);
	ObDereferenceObject(DiskDriver);
	DiskDriver = NULL;
}


NTSTATUS DispatchRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UnhookDiskDriver();
	ExFreePool(DriverRegistryPath.Buffer);
}

#define READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define SET_PID_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

PDEVICE_OBJECT DeviceObject;
UNICODE_STRING dev, dos;

DWORD PID;
DWORD64 MainModule;
PEPROCESS process;

NTSTATUS NTAPI MmCopyVirtualMemory(IN PEPROCESS  	SourceProcess,
	IN PVOID  	SourceAddress,
	IN PEPROCESS  	TargetProcess,
	OUT PVOID  	TargetAddress,
	IN SIZE_T  	BufferSize,
	IN KPROCESSOR_MODE  	PreviousMode,
	OUT PSIZE_T  	ReturnSize
);

NTKERNELAPI
PVOID
PsGetProcessSectionBaseAddress(
	__in PEPROCESS Process
);

typedef struct _READ_MEM
{
	DWORD64 address;
	DWORD64 response;
	ULONG size;

} READ_MEM, *PREAD_MEM;

typedef struct _WRITE_MEM
{
	DWORD64 address;
	float value;
	ULONG size;

} WRITE_MEM, *PWRITE_MEM;


NTSTATUS RPM(PVOID src, PVOID dest, SIZE_T size)
{
	PSIZE_T bytes;
	__try
	{
		// Checks if the memory address actually exists
		ProbeForRead(src, size, (ULONG)size);
		// Use MmCopyVirtualMemory to copy memory from the game to our usermode process
		if (NT_SUCCESS(MmCopyVirtualMemory(process, src, PsGetCurrentProcess(), dest, size, KernelMode, &bytes)))
			return STATUS_SUCCESS;
		else
			return STATUS_ACCESS_DENIED;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS WPM(PVOID src, PVOID dest, SIZE_T size)
{
	PSIZE_T bytes;
	__try
	{
		// Checks if the memory address actually exists and is writable
		ProbeForWrite(dest, size, (ULONG)size);
		// Use MmCopyVirtualMemory to copy memory from our usermode process to the game
		if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), src, process, dest, size, KernelMode, &bytes)))
			return STATUS_SUCCESS;
		else
			return STATUS_ACCESS_DENIED;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS IoControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	// Get the IOCTL code
	ULONG IOcode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (IOcode == READ_REQUEST)
	{
		// Get the struct address from the irp buffer
		PREAD_MEM read = (PREAD_MEM)Irp->AssociatedIrp.SystemBuffer;

		// Check if address is in usermode virtual memory (the usermode app sometimes fuck up for some reason)
		if (read->address < 0x7FFFFFFFFFFF)
		{
			PsLookupProcessByProcessId((HANDLE)PID, &process);
			RPM(read->address, &read->response, read->size);
		}

		status = STATUS_SUCCESS;
		bytes = sizeof(PREAD_MEM);
	}
	else if (IOcode == WRITE_REQUEST)
	{
		// Get the struct address from the irp buffer
		PWRITE_MEM write = (PWRITE_MEM)Irp->AssociatedIrp.SystemBuffer;

		// Check if address is in usermode virtual memory (the usermode app sometimes fuck up for some reason)
		if (write->address < 0x7FFFFFFFFFFF)
		{
			PsLookupProcessByProcessId((HANDLE)PID, &process);
			WPM(&write->value, write->address, write->size);
		}

		status = STATUS_SUCCESS;
		bytes = sizeof(PWRITE_MEM);
	}
	else if (IOcode == SET_PID_REQUEST)
	{
		// Get address of var where to read the PID from
		PULONG Input = (PULONG)Irp->AssociatedIrp.SystemBuffer;
		PID = *Input;

		status = STATUS_SUCCESS;
		bytes = sizeof(Input);
	}
	else if (IOcode == GET_MODULE_REQUEST)
	{
		// Get address of var where to store the main mdoule base address
		PDWORD64 Module = (PDWORD64)Irp->AssociatedIrp.SystemBuffer;
		PsLookupProcessByProcessId((HANDLE)PID, &process);

		// Attach to the process and get it's base
		KeAttachProcess((PKPROCESS)process);
		*Module = PsGetProcessSectionBaseAddress(process);
		KeDetachProcess();

		status = STATUS_SUCCESS;
		bytes = sizeof(Module);
	}

	// Finish our request
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytes;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DriverInitialize(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG i = 0;
	UNICODE_STRING dev, dos;
	RtlInitUnicodeString(&dev, L"\\Device\\MegaBypassDriver");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\MegaBypassDriver");

	IoCreateDevice(DriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DriverObject);
	IoCreateSymbolicLink(&dos, &dev);

	DriverRegistryPath.Buffer = ExAllocatePool(NonPagedPool,
		RegistryPath->Length + sizeof(UNICODE_NULL));
	if (!DriverRegistryPath.Buffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	DriverRegistryPath.Length = RegistryPath->Length;
	DriverRegistryPath.MaximumLength = DriverRegistryPath.Length + sizeof(UNICODE_NULL);
	RtlZeroMemory(DriverRegistryPath.Buffer, DriverRegistryPath.MaximumLength);
	RtlMoveMemory(DriverRegistryPath.Buffer, RegistryPath->Buffer,
		RegistryPath->Length);
	KdPrint(("[br]DriverRegistryPath:%ws\n", DriverRegistryPath.Buffer));


	SetOriginSNInfo();

	if (HookDiskDriver()) {
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchRoutine;
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchRoutine;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
		DriverObject->DriverUnload = DriverUnload;
		Hooks_Apply();
		status = STATUS_SUCCESS;
	}

	return status;
}

NTKERNELAPI
NTSTATUS
IoCreateDriver(
	IN PUNICODE_STRING DriverName, OPTIONAL
	IN PDRIVER_INITIALIZE InitializationFunction
);

NTSTATUS DriverEntry(_In_  struct _DRIVER_OBJECT *DriverObject,
	_In_  PUNICODE_STRING RegistryPath)
{
	NTSTATUS        status;
	UNICODE_STRING drv_name;
	RtlInitUnicodeString(&drv_name, L"\\Driver\\MegaBypassDriver");
	status = IoCreateDriver(&drv_name, &DriverInitialize);

	return status;
}