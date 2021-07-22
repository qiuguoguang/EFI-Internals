/** @file
  Displays a user-specified BMP image.

  Copyright (C) Microsoft Corporation. All rights reserved.
  
  2021/05/18 PTEC MCH - Add VBT RAW DATA Dump Extention for Intel Platforms
  2021/05/18 PTEC MCH - Add RW SETUP ITEM Extention for Intel Platforms
  2021/05/21 PTEC MCH - Add IA CPU int1 BP test
  2021/07/22 PTEC MCH - Add Print Pci Cfg Extention

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BmpSupportLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/IoLib.h>

//#include <Library/DebugLib.h>
#include <Protocol/GopPolicy.h>
#include <SetupVariable.h>

#define MAX_NUMBER_OF_ARGS    1

extern VOID CpuIceBreakpoint();

VOID
EFIAPI
CpuIceBreakpoint();

EFI_STATUS GopVbtDump(IN CHAR16     *Name);
EFI_STATUS PrintPciCfg (UINT8 BusNo, UINT8 DevNo, UINT8 FuncNo);
void RwSetupItem(IN CHAR16     *Name);

STATIC CONST SHELL_PARAM_ITEM mParamList[] = {
  {L"-?",                      TypeFlag},   // ? - Help
  {L"-h",                      TypeFlag},   // h - Help
  {L"-o",                      TypeFlag},   // o - VBT Dump
  {L"-p",                      TypeFlag},   // p - PciCfg Dump
  {L"-v",                      TypeFlag},   // v - RW Designated Setup Item
  {L"-i",                      TypeValue},  // i - Input file path
  {NULL,                       TypeMax},
  };

/**
  Displays application usage information.

**/
VOID
PrintUsage (
  VOID
  )
{
  Print (
    L"%a Version 1.0\n"
    L"Copyright (C) Microsoft Corporation. All rights reserved.\n"
    L"Copyright (C) PTEC MCH. All rights reserved.\n"
    L"\n"
    L"Displays a BMP image.\n"
    L"&Dump VBT RAW DATA with -o option\n"
    L"&Print PciCfg with -p option\n"
    L"&Rw SETUP ITEM with -v option\n"
    L"\n"
    L"usage: BmpDisplay -i inputfile\n"
    L"  -i    Specifies the BMP input file path.\n"
    L"\n",
    gEfiCallerBaseName
    );

  return;
}

/**
  Parses application command line arguments.

  Returns a BmpFilePath string if a valid argument is parsed from command line input.

  @param[out] BmpFilePath               A pointer to a pointer that will be set to the BMP file path provided
                                        as an application command line argument.

  @retval EFI_SUCCESS                   The command line was parsed successfully.
  @retval EFI_INVALID_PARAMETER         The BmpFilePath actual parameter is NULL or the user provided too many
                                        arguments or an invalid argument value.
  @retval EFI_VOLUME_CORRUPTED          An error occurred parsing command line arguments.

**/
EFI_STATUS
ParseCommandLine (
  OUT CONST CHAR16      **BmpFilePath
  )
{
  EFI_STATUS            Status;
  LIST_ENTRY            *Package;
  CHAR16                *ProblemParam;
  CONST CHAR16          *LocalBmpFilePath;

  CHAR16                VBT[10];
  CHAR16                ITEM[20];
  UINT8                 BusNo;
  UINT8                 DevNo;
  UINT8                 FuncNo;
  
  BusNo = 0;
  DevNo = 6;
  FuncNo = 0;

  Package = NULL;
  ProblemParam = NULL;

  if (BmpFilePath == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = ShellCommandLineParse (mParamList, &Package, &ProblemParam, FALSE);
  if (EFI_ERROR (Status)) {
    if (Status == EFI_VOLUME_CORRUPTED && ProblemParam != NULL) {
      Print (L"Error: Unknown parameter input: %s\n", ProblemParam);
      goto Done;
    }
  }

  if (ShellCommandLineGetCount (Package) > MAX_NUMBER_OF_ARGS) {
    Print (L"Error: Too many arguments. Maximum of %d expected.\n", MAX_NUMBER_OF_ARGS);
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  if (ShellCommandLineGetFlag (Package, L"-?") || ShellCommandLineGetFlag (Package, L"-h")) {
    PrintUsage ();
    Status = EFI_SUCCESS;
    *BmpFilePath = NULL;
    goto Done;
  }

  AsciiStrToUnicodeStrS("VBT.bin", VBT, sizeof(VBT) / sizeof(CHAR16));
  if (ShellCommandLineGetFlag (Package, L"-o")) {
    //Status = GopVbtDump (L"VBT.bin");
    Status = GopVbtDump (VBT);
    if(!EFI_ERROR(Status)){
      Print(L"GOP VBT dumped successfully\n");
      Status = EFI_SUCCESS;
    }
    goto Done;
  }
  
  if (ShellCommandLineGetFlag (Package, L"-p")) {
    //Status = PrintPciCfg (UINT8 BusNo, UINT8 DevNo, UINT8 FuncNo);
    Status = PrintPciCfg (BusNo, DevNo, FuncNo);
    if(!EFI_ERROR(Status)){
      Print(L"Print PciCfg successfully\n");
      Status = EFI_SUCCESS;
    }
    goto Done;
  }
  
  AsciiStrToUnicodeStrS("FprrEnable", ITEM, sizeof(ITEM) / sizeof(CHAR16));
  if (ShellCommandLineGetFlag (Package, L"-v")) {
    RwSetupItem (ITEM);
    goto Done;
  }

  LocalBmpFilePath = ShellCommandLineGetValue (Package, L"-i");
  if (LocalBmpFilePath == NULL) {
    Print (L"Error: An input BMP file must be specified.\n");
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  *BmpFilePath = LocalBmpFilePath;

Done:
  if (ProblemParam != NULL) {
    FreePool (ProblemParam);
  }

  return Status;
}

/**
  This function write a buffer to a file

  @param[in] Buffer          Pointer to buffer
  @param[in] Size            Number of bytes
  @param[in] FileName        File name

  @retval EFI_SUCCESS        The function completed successfully.
**/
EFI_STATUS
WriteBufferToFile (
  IN VOID       *Buffer,
  IN UINTN      Size,
  IN CHAR16     *Name
  )
{
  EFI_STATUS              Status;
  SHELL_FILE_HANDLE       FileHandle;
  
  Status = ShellFileExists(Name);
  if(!EFI_ERROR(Status)){
    Print(L"File %s Is Existing\n",Name);
    return EFI_INVALID_PARAMETER;
  }

  Status = ShellOpenFileByName(Name, &FileHandle, EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_CREATE, 0);
  if(EFI_ERROR(Status)){
    Print(L"Cannot create file %s to write!\n", Name);
    return Status;
  }

  Status = ShellWriteFile(FileHandle, &Size, Buffer);
  if(EFI_ERROR(Status)){
    Print(L"Cannot write the file %s!\n", Name);
    ShellCloseFile(&FileHandle);
    return Status;
  }

  ShellCloseFile(&FileHandle);
  return EFI_SUCCESS;
}

EFI_STATUS
GopVbtDump(IN CHAR16     *Name)
{
  GOP_POLICY_PROTOCOL          *GopPolicy;
  EFI_PHYSICAL_ADDRESS         VbtAddress;
  UINT32                       Size;
  EFI_STATUS                   Status;
  
  //DEBUG ((DEBUG_INFO, "[GopVbtDump][PTEC][MCH] Locate GopPolicy and GetVbtData\n"));
 
  //
  // Locate the GOP Policy Protocol.
  //
  GopPolicy = NULL;
  Status = gBS->LocateProtocol (
                  &gGopPolicyProtocolGuid,
                  NULL,
                  &GopPolicy
                  );

  if (EFI_ERROR (Status) || (GopPolicy == NULL)) {
    return EFI_NOT_FOUND;
  }
  
  //
  // Get VBT data
  //
  VbtAddress      = 0;
  Size            = 0;

  Status          = GopPolicy->GetVbtData (&VbtAddress, &Size);
  if (EFI_ERROR (Status)) {
    return EFI_NOT_READY;
  }
  
  Status = WriteBufferToFile((VOID *)VbtAddress,Size,Name);
  if (EFI_ERROR (Status)) {
    return EFI_NOT_READY;
  }
  
  return Status;
}

EFI_STATUS
PrintPciCfg (UINT8 BusNo, UINT8 DevNo, UINT8 FuncNo)
{
   UINT32 DevAddr;
   UINT8  PciData8;

   UINT8  Bus;
   UINT8  Dev;
   UINT8  Func;
   UINT16 Reg;
   UINT8  Index;

   DevAddr = 0x0;
   PciData8 = 0x0;
   Bus = BusNo;
   Dev = DevNo;
   Func = FuncNo;
   Reg = 0x0;
   Index = 0x0;

   Print(L"\n");
   for (Reg = 0x00; Reg < 0x100; Reg = Reg + 4)
   {
     for(Index = 0x0; Index < 4; Index ++)
     {
       DevAddr =  0x80000000 + (Bus << 16) + (Dev << 11) + (Func << 8) + (Reg + Index);
       IoWrite32(0xCF8, DevAddr);
       PciData8 = IoRead8(0xCFC + Index);
       Print(L"%02x ",PciData8);
       if(((Reg + Index) % 0x10) == 0xF){
          Print(L"\n");
       }
     }
   }

   return EFI_SUCCESS;
}

void RwSetupItem(IN CHAR16     *Name)
{
  EFI_STATUS                   Status;
  EFI_INPUT_KEY                Key;
  UINTN                        Index;
#if 0
  UINTN                        CpuVarSize;
  UINTN                        SaVarSize;
  CPU_SETUP                    CpuSetup;
  SA_SETUP                     SaSetup;
#endif
  UINTN                        PchVarSize;
  PCH_SETUP                    PchSetup;

#if 0
  CpuVarSize = sizeof (CPU_SETUP);
  Status = gRT->GetVariable (
                  L"CpuSetup",
                  &gCpuSetupVariableGuid,
                  NULL,
                  &CpuVarSize,
                  &CpuSetup
                  );

  if (EFI_ERROR(Status)) 
  {
    Print(L"Get Intel CpuSetup Error\n");
    return;
  }

  SaVarSize = sizeof (SA_SETUP);
  Status = gRT->GetVariable (
                  L"SaSetup",
                  &gSaSetupVariableGuid,
                  NULL,
                  &SaVarSize,
                  &SaSetup
                  );
   
  if (EFI_ERROR(Status)) 
  {
    Print(L"Get Intel SaSetup Error\n");
    return;
  }
#endif
  PchVarSize = sizeof (PCH_SETUP);
  Status = gRT->GetVariable (
                  L"PchSetup",
                  &gPchSetupVariableGuid,
                  NULL,
                  &PchVarSize,
                  &PchSetup
                  );
   
  if (EFI_ERROR(Status)) 
  {
    Print(L"Get Intel PchSetup Error\n");
    return;
  }

  Print(L"FprrEnable = %d\n",PchSetup.FprrEnable);
  Print(L"Press Enter to Continue\n");
  while (TRUE) {
    Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    if (!EFI_ERROR (Status)) {
      break;
    }

    if (Status != EFI_NOT_READY) {
      continue;
    }

    Print(L"%c",Key.UnicodeChar);
    CpuIceBreakpoint();
	
    gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &Index);
  }

  //gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR (EFI_WHITE, EFI_LIGHTCYAN));

  if (Key.UnicodeChar != CHAR_CARRIAGE_RETURN) {
    Print(L"Invalid Input Key\n");
    return;
  }

  if (PchSetup.FprrEnable == 1) {
    PchSetup.FprrEnable = 0;
  }

  if (PchSetup.FprrEnable == 0) {
    PchSetup.FprrEnable = 1;
  }

#if 0
  Status = gRT->SetVariable (
                  L"CpuSetup",
                  &gCpuSetupVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                  CpuVarSize,
                  &CpuSetup
                  );
				  
  if (EFI_ERROR(Status)) 
  {
    Print(L"Set CpuSetup Error\n");
    return;
  }

  Status = gRT->SetVariable (
                  L"SaSetup",
                  &gSaSetupVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                  SaVarSize,
                  &SaSetup
                  );
				  
  if (EFI_ERROR(Status)) 
  {
    Print(L"Set SaSetup Error\n");
    return;
  }
#endif
  Status = gRT->SetVariable (
                  L"PchSetup",
                  &gPchSetupVariableGuid,
                  EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                  PchVarSize,
                  &PchSetup
                  );
				  
  if (EFI_ERROR(Status)) 
  {
    Print(L"Set PchSetup Error\n");
    return;
  }

  Print(L"Reset 3 Sec Later\n");
  gBS->Stall(3*1000*1000);
  gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
}

/**
  Application entry point.

  @param[in] ImageHandle                The firmware allocated handle for the EFI image.
  @param[in] SystemTable                A pointer to the EFI System Table.

  @retval EFI_SUCCESS                   The entry point is executed successfully.
  @retval EFI_NOT_FOUND                 A GOP instance was not found or the BMP file requested was not found.
  @retval EFI_LOAD_ERROR                An error occurred loading the specified BMP file.
  @retval EFI_VOLUME_CORRUPTED          An error occurred parsing the given command line arguments or reading the
                                        BMP file into memory.
  @retval EFI_INVALID_PARAMETER         A command line parameter is invalid or the SystemTable pointer is NULL.
  @retval EFI_OUT_OF_RESOURCES          Insufficient memory resources are available to allocate a memory buffer.
  @retval EFI_ABORTED                   An error occurred while processing the BMP image that led the application
                                        to abort further execution.
  @retval EFI_DEVICE_ERROR              An error occurred interacting with the video frame buffer.

**/
EFI_STATUS
EFIAPI
BmpDisplayEntrypoint (
  IN EFI_HANDLE           ImageHandle,
  IN EFI_SYSTEM_TABLE     *SystemTable
  )
{
  EFI_STATUS                        Status;
  CONST CHAR16                      *BmpFilePath;
  CONST CHAR16                      *BmpFullFilePath;
  VOID                              *BmpFileData;
  VOID                              *OriginalVideoBufferData;
  EFI_GRAPHICS_OUTPUT_PROTOCOL      *GraphicsOutput;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL     *Blt;
  EFI_FILE_INFO                     *BmpFileInfo;
  BOOLEAN                           CursorModified;
  BOOLEAN                           CursorVisible;
  SHELL_FILE_HANDLE                 BmpFileHandle;
  EFI_INPUT_KEY                     Key;
  UINTN                             EventIndex;
  UINTN                             OriginalVideoBltBufferSize;
  UINTN                             BmpFileSize;
  UINTN                             BltSize;
  UINTN                             ImageWidth;
  UINTN                             ImageHeight;
  INTN                              ImageDestinationX;
  INTN                              ImageDestinationY;
  UINT32                            HorizontalResolution;
  UINT32                            VerticalResolution;

  CursorModified = FALSE;
  BmpFileData = NULL;
  OriginalVideoBufferData = NULL;

  Status = ParseCommandLine (&BmpFilePath);
  if (EFI_ERROR (Status) || BmpFilePath == NULL) {
    return Status;
  }

  if (SystemTable == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  gST = SystemTable;

  //
  // First, try to open GOP on the Console Out handle. If that fails, try a global database search.
  //
  Status = gBS->HandleProtocol (SystemTable->ConsoleOutHandle, &gEfiGraphicsOutputProtocolGuid, (VOID **) &GraphicsOutput);
  if (EFI_ERROR (Status)) {
    Status = gBS->LocateProtocol (&gEfiGraphicsOutputProtocolGuid, NULL, (VOID **) &GraphicsOutput);
    if (EFI_ERROR (Status)) {
      Print (L"Error: Could not find a GOP instance!\n");
      Status = EFI_NOT_FOUND;
      goto Done;
    }
  }

  //
  // Open the BMP file path requested
  //
  BmpFullFilePath = ShellFindFilePath (BmpFilePath);
  if (BmpFullFilePath == NULL) {
    Print (L"Error: The BMP file path %s could not be found\n", BmpFilePath);
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  Status = ShellIsFile (BmpFullFilePath);
  if (EFI_ERROR (Status)) {
    Print (L"Error: The BMP file path %s is invalid\n", BmpFilePath);
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  Status = ShellOpenFileByName (BmpFullFilePath, &BmpFileHandle, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) {
    Print (L"Error: Could not read the BMP file %s\n", BmpFullFilePath);
    Status = EFI_LOAD_ERROR;
    goto Done;
  }

  BmpFileInfo = ShellGetFileInfo (BmpFileHandle);
  if (BmpFileInfo == NULL) {
    Print (L"Error: Failed to get file info for the BMP file %s\n", BmpFullFilePath);
    Status = EFI_LOAD_ERROR;
    goto Done;
  }
  BmpFileSize = (UINTN) BmpFileInfo->FileSize;

  BmpFileData = AllocateZeroPool (BmpFileSize);
  if (BmpFileData == NULL) {
    Print (L"Error: Insufficient memory available to load BMP file.\n  BMP file name: %s\n  BMP file size: %s\n", BmpFullFilePath, BmpFileSize);
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  Status = ShellReadFile (BmpFileHandle, &BmpFileSize, BmpFileData);
  ShellCloseFile (&BmpFileHandle);
  BmpFileHandle = NULL;
  if (EFI_ERROR (Status)) {
    Print (L"Error: Could not read BMP file %s\n", BmpFullFilePath);
    Status = EFI_VOLUME_CORRUPTED;
    goto Done;
  }

  HorizontalResolution = GraphicsOutput->Mode->Info->HorizontalResolution;
  VerticalResolution = GraphicsOutput->Mode->Info->VerticalResolution;

  if (SystemTable->ConOut != NULL) {
    CursorModified = TRUE;
    CursorVisible = SystemTable->ConOut->Mode->CursorVisible;
    SystemTable->ConOut->EnableCursor (SystemTable->ConOut, FALSE);
  }

  //
  // Translate the GOP image buffer to a BLT buffer
  //
  Blt = NULL;
  ImageWidth = 0;
  ImageHeight = 0;
  Status =  TranslateBmpToGopBlt (
              BmpFileData,
              BmpFileSize,
              &Blt,
              &BltSize,
              &ImageHeight,
              &ImageWidth
              );
  if (EFI_ERROR (Status)) {
    Print (L"Error: An error occurred translating the BMP to a GOP BLT - %r.\n", Status);
    goto Done;
  }

  Print (L"Image information:\n");
  Print (L"  File name: %s\n  File size: 0x%x\n", BmpFullFilePath, BmpFileSize);
  Print (L"  Dimensions: %d x %d.\n", ImageWidth, ImageHeight);

  if (ImageWidth > HorizontalResolution) {
    Print (L"Error: The image width (%d px) is too wide for the horizontal resolution (%d px).\n", ImageWidth, HorizontalResolution);
    Status = EFI_ABORTED;
    goto Done;
  }
  if (ImageHeight > VerticalResolution) {
    Print (L"Error: The image height (%d px) is too tall for the vertical resolution (%d px).\n", ImageHeight, VerticalResolution);
    Status = EFI_ABORTED;
    goto Done;
  }

  //
  // Backup the current buffer in the area that will be covered by the image
  //
  OriginalVideoBltBufferSize = ImageWidth * ImageHeight * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL);

  OriginalVideoBufferData = AllocateZeroPool (OriginalVideoBltBufferSize);
  if (OriginalVideoBufferData == NULL) {
    Print (L"Error: Insufficient memory available to allocate a BLT buffer of size 0x%x\n", OriginalVideoBltBufferSize);
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  ImageDestinationX = (HorizontalResolution - ImageWidth) / 2;
  ImageDestinationY = (VerticalResolution - ImageHeight) / 2;

  if (ImageDestinationX < 0 || ImageDestinationY < 0) {
    Print (L"Error: The image size and/or orientation are invalid for this display.\n");
    Status = EFI_ABORTED;
    goto Done;
  }

  Status =  GraphicsOutput->Blt (
                              GraphicsOutput,
                              OriginalVideoBufferData,
                              EfiBltVideoToBltBuffer,
                              (UINTN) ImageDestinationX,
                              (UINTN) ImageDestinationY,
                              0,
                              0,
                              ImageWidth,
                              ImageHeight,
                              ImageWidth * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
                              );
  if (EFI_ERROR (Status)) {
    Print (L"Error: An error occurred reading from the video frame buffer!\n");
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  //
  // Output the BMP image
  //
  Status =  GraphicsOutput->Blt (
                              GraphicsOutput,
                              Blt,
                              EfiBltBufferToVideo,
                              0,
                              0,
                              (UINTN) ImageDestinationX,
                              (UINTN) ImageDestinationY,
                              ImageWidth,
                              ImageHeight,
                              ImageWidth * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
                              );
  if (EFI_ERROR (Status)) {
    Print (L"Error: An error occurred writing to the video frame buffer!\n");
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  //
  // Stop showing the image when a key is pressed
  //
  while (TRUE) {
    Status = SystemTable->ConIn->ReadKeyStroke (SystemTable->ConIn, &Key);
    if (!EFI_ERROR (Status)) {
      break;
    }

    if (Status != EFI_NOT_READY) {
      continue;
    }

    // Wait for another key press
    gBS->WaitForEvent (1, &SystemTable->ConIn->WaitForKey, &EventIndex);
  }

  //
  // Restore the original BLT buffer from the image area
  //
  Status =  GraphicsOutput->Blt (
                              GraphicsOutput,
                              OriginalVideoBufferData,
                              EfiBltBufferToVideo,
                              0,
                              0,
                              (UINTN) ImageDestinationX,
                              (UINTN) ImageDestinationY,
                              ImageWidth,
                              ImageHeight,
                              ImageWidth * sizeof (EFI_GRAPHICS_OUTPUT_BLT_PIXEL)
                              );
  if (EFI_ERROR (Status)) {
    Print (L"Error: An error occurred writing to the video frame buffer!\n");
    Status = EFI_DEVICE_ERROR;
  }

Done:
  if (CursorModified) {
    SystemTable->ConOut->EnableCursor (SystemTable->ConOut, CursorVisible);
  }

  if (Blt != NULL) {
    FreePool (Blt);
  }
  if (BmpFileData != NULL) {
    FreePool (BmpFileData);
  }
  if (OriginalVideoBufferData != NULL) {
    FreePool (OriginalVideoBufferData);
  }

  return Status;
}
