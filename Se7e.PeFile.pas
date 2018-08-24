unit Se7e.PeFile;

interface

uses
  Classes,
  Types,
  System.SysUtils,
  Se7e.PEFile.API;

type

  TPeFileType = (PE32, PE64);
  TFileOffset = type UInt64;

  TPeMzHeader = record
    MagicNumber: WORD;
    BytesOnLastPage: WORD;
    PagesInFile: WORD;
    Relocations: WORD;
    SizeOfHeader: WORD;
    MinExtraParagraphs: WORD;
    MaxExtraParagraphs: WORD;
    InitialStackSegment: WORD;
    InitialStackPointer: WORD;
    Checksum: WORD;
    InitialInstructionPointer: WORD;
    InitialCodeSegment: WORD;
    AddressOfRelocationTable: WORD;
    OverlayNumber: WORD;
    ReservedWords1: array[0..3] of WORD;
    OemIdentifier: WORD;
    OemInformation: WORD;
    ReservedWords2: array[0..9] of WORD;
    AddressOfPeHeader: DWORD;
    procedure Assign(const DosHeader: TImageDosHeader);
  end;

  TPeHeader = record
    NtSignature: DWORD;
    Machine: WORD;
    NumberOfSections: WORD;
    TimeDateStamp: DWORD;
    PointerToSymbolTable: DWORD;
    NumberOfSymbols: DWORD;
    SizeOfOptionalHeader: WORD;
    Characteristics: WORD;
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    ImageBase: ULONGLONG;
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: Word;
    MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word;
    MinorImageVersion: Word;
    MajorSubsystemVersion: Word;
    MinorSubsystemVersion: Word;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: Word;
    DllCharacteristics: Word;
    SizeOfStackReserve: ULONGLONG;
    SizeOfStackCommit: ULONGLONG;
    SizeOfHeapReserve: ULONGLONG;
    SizeOfHeapCommit: ULONGLONG;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: packed array[0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES-1] of TImageDataDirectory;
    procedure Assign(const FileHeader: TImageFileHeader); overload;
    procedure Assign(const Header32: TImageOptionalHeader32); overload;
    procedure Assign(const Header64: TImageOptionalHeader64); overload;
  end;

  TPEFile = record
    PeMzHeader: TPeMzHeader;
    PeHeader: TPeHeader;
  end;

  function OpenPeFile(const FileName: string): TPEFile;

implementation

uses
  stdio;

function GetPeFileType(const FileName: string): TPeFileType;
var
  magic,
  machine: WORD;
begin

end;

function OpenPeFile(const FileName: string): TPEFile;
var
  DosHeader: TImageDosHeader;
  Header32: TImageOptionalHeader32;
  Header64: TImageOptionalHeader64;
  FileHeader: TImageFileHeader;
  OffsetCabecalhosOpcionais, DataDirOfs,
  OffsetCabecalhosSecoes,
  OffsetFimCabecalhosSecoes,
  SecDataOfs: TFileOffset;
  Stream: THandle;
  Signature: DWORD;
  PEFile: TPEFile absolute Result;
begin
  FillChar(DosHeader, SizeOf(DosHeader), #0);
  FillChar(Header32, SizeOf(Header32), #0);
  FillChar(Header64, SizeOf(Header64), #0);
  FillChar(FileHeader, SizeOf(FileHeader), #0);
  FillChar(Result, SizeOf(FileHeader), #0);
  FillChar(PEFile, SizeOf(PEFile), #0);

  Stream := fopen(FileName, 'r');

  fseek(Stream, 0, SEEK_END);
  if ftell(Stream) < SizeOf(DosHeader)  then
    raise Exception.Create('arquivo invalido');

   rewind(Stream);
  if fread(DosHeader, 1, SizeOf(DosHeader), Stream) <> SizeOf(DosHeader) then
    raise Exception.Create('Falha na leitura de DOsHeader');

  if DosHeader.MagicNumber <> IMAGE_DOS_SIGNATURE then
    raise Exception.Create('formato de arquivo desconhecido');

  if (DosHeader.AddressOfPeHeader = 0) then
    raise Exception.Create('Isso é provavelmente executável de 16 bits.');

  // Verifica se PE ofs < 256 MB (Veja RtlImageNtHeaderEx)
  if (DosHeader.AddressOfPeHeader >= 256 * 1024 * 1024) then
    raise Exception.Create('e_lfanew >= 256 MB');

  if (DosHeader.AddressOfPeHeader mod IMAGE_SCN_ALIGN_4BYTES) <> 0 then
    raise Exception.Create('O cabeçalho de PE não está alinhado corretamente.');

  if (DosHeader.AddressOfPeHeader <= SizeOf(TImageDOSHeader)) then
    raise Exception.CreateFmt('e_lfanew aponta para si mesmo (0x%x)', [DosHeader.AddressOfPeHeader]);

  fSeek(Stream, DosHeader.AddressOfPeHeader, SEEK_SET);
  if fread(Signature, 1, SizeOf(Signature), Stream) <> SizeOf(Signature) then
    raise Exception.Create('Falha na Leitura de Signature');

  if Signature <> IMAGE_NT_SIGNATURE then
    raise Exception.Create('formato de arquivo desconhecido');

  PEFile.PeMzHeader.Assign(DosHeader);

  if fread(FileHeader, 1, SizeOf(FileHeader), Stream) <> SizeOf(FileHeader) then
    raise Exception.Create('Falha na Leitura de FileHeader');

  PEFile.PeHeader.Assign(FileHeader);

  // Obter offsets do cabeçalho opcional e dos cabeçalhos de seção.
  OffsetCabecalhosOpcionais := ftell(Stream);
  OffsetCabecalhosSecoes := OffsetCabecalhosOpcionais + FileHeader.SizeOfOptionalHeader;
  OffsetFimCabecalhosSecoes := OffsetCabecalhosSecoes + SizeOf(TImageSectionHeader) * FileHeader.NumberOfSections;

  fseek(Stream, OffsetCabecalhosOpcionais, SEEK_SET);

  if FileHeader.Machine = IMAGE_FILE_MACHINE_I386 then
  begin
    if fread(Header32, 1, SizeOf(Header32), Stream) <> SizeOf(Header32) then
      raise Exception.Create('Falha na Leitura de NtHeaders32.OptionalHeader');

    if Header32.Magic <> IMAGE_NT_OPTIONAL_HDR32_MAGIC then
      raise Exception.Create('formato de arquivo desconhecido');

    PEFile.PeHeader.Assign(Header32);
  end
  else if FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64 then
  begin
    if fread(Header64, 1, SizeOf(Header64), Stream) <> SizeOf(Header64) then
      raise Exception.Create('Falha na Leitura de NtHeaders64.OptionalHeader');

    if Header64.Magic <> IMAGE_NT_OPTIONAL_HDR64_MAGIC then
      raise Exception.Create('formato de arquivo desconhecido');

    PEFile.PeHeader.Assign(Header64);
  end
  else
    raise Exception.Create('tipo de arquivo não suportado');

  fclose(Stream);
end;

{ TPeMzHeader }

procedure TPeMzHeader.Assign(const DosHeader: TImageDosHeader);
begin
  Self.MagicNumber := DosHeader.MagicNumber;
  Self.BytesOnLastPage := DosHeader.BytesOnLastPage;
  Self.PagesInFile := DosHeader.PagesInFile;
  Self.Relocations := DosHeader.Relocations;
  Self.SizeOfHeader := DosHeader.SizeOfHeader;
  Self.MinExtraParagraphs := DosHeader.MinExtraParagraphs;
  Self.MaxExtraParagraphs := DosHeader.MaxExtraParagraphs;
  Self.InitialStackSegment := DosHeader.InitialStackSegment;
  Self.InitialStackPointer := DosHeader.InitialStackPointer;
  Self.Checksum := DosHeader.Checksum;
  Self.InitialInstructionPointer := DosHeader.InitialInstructionPointer;
  Self.InitialCodeSegment := DosHeader.InitialCodeSegment;
  Self.AddressOfRelocationTable := DosHeader.AddressOfRelocationTable;
  Self.OverlayNumber := DosHeader.OverlayNumber;
  Self.ReservedWords1[0] := DosHeader.ReservedWords1[0];
  Self.ReservedWords1[1] := DosHeader.ReservedWords1[1];
  Self.ReservedWords1[2] := DosHeader.ReservedWords1[2];
  Self.OemIdentifier := DosHeader.OemIdentifier;
  Self.OemInformation := DosHeader.OemInformation;
  Self.ReservedWords2[0] := DosHeader.ReservedWords2[0];
  Self.ReservedWords2[1] := DosHeader.ReservedWords2[1];
  Self.ReservedWords2[2] := DosHeader.ReservedWords2[2];
  Self.ReservedWords2[3] := DosHeader.ReservedWords2[3];
  Self.ReservedWords2[4] := DosHeader.ReservedWords2[4];
  Self.ReservedWords2[5] := DosHeader.ReservedWords2[5];
  Self.ReservedWords2[6] := DosHeader.ReservedWords2[6];
  Self.ReservedWords2[7] := DosHeader.ReservedWords2[7];
  Self.ReservedWords2[8] := DosHeader.ReservedWords2[8];
  Self.ReservedWords2[9] := DosHeader.ReservedWords2[9];
  Self.AddressOfPeHeader := DosHeader.AddressOfPeHeader;
end;

{ TPeHeader }

procedure TPeHeader.Assign(const FileHeader: TImageFileHeader);
begin
  Self.Machine := FileHeader.Machine;
  Self.NumberOfSections := FileHeader.NumberOfSections;
  Self.TimeDateStamp := FileHeader.TimeDateStamp;
  Self.PointerToSymbolTable := FileHeader.PointerToSymbolTable;
  Self.NumberOfSymbols := FileHeader.NumberOfSymbols;
  Self.SizeOfOptionalHeader := FileHeader.SizeOfOptionalHeader;
  Self.Characteristics := FileHeader.Characteristics;
end;

procedure TPeHeader.Assign(const Header32: TImageOptionalHeader32);
var
  i: Integer;
begin
  Self.Magic := Header32.Magic;
  Self.MajorLinkerVersion := Header32.MajorLinkerVersion;
  Self.MinorLinkerVersion := Header32.MinorLinkerVersion;
  Self.SizeOfCode := Header32.SizeOfCode;
  Self.SizeOfInitializedData := Header32.SizeOfInitializedData;
  Self.SizeOfUninitializedData := Header32.SizeOfUninitializedData;
  Self.AddressOfEntryPoint := Header32.AddressOfEntryPoint;
  Self.BaseOfCode := Header32.BaseOfCode;
  Self.ImageBase := Header32.ImageBase;
  Self.SectionAlignment := Header32.SectionAlignment;
  Self.FileAlignment := Header32.FileAlignment;
  Self.MajorOperatingSystemVersion := Header32.MajorOperatingSystemVersion;
  Self.MinorOperatingSystemVersion := Header32.MinorOperatingSystemVersion;
  Self.MajorImageVersion := Header32.MajorImageVersion;
  Self.MinorImageVersion := Header32.MinorImageVersion;
  Self.MajorSubsystemVersion := Header32.MajorSubsystemVersion;
  Self.MinorSubsystemVersion := Header32.MinorSubsystemVersion;
  Self.Win32VersionValue := Header32.Win32VersionValue;
  Self.SizeOfImage := Header32.SizeOfImage;
  Self.SizeOfHeaders := Header32.SizeOfHeaders;
  Self.CheckSum := Header32.CheckSum;
  Self.Subsystem := Header32.Subsystem;
  Self.DllCharacteristics := Header32.DllCharacteristics;
  Self.SizeOfStackReserve := Header32.SizeOfStackReserve;
  Self.SizeOfStackCommit := Header32.SizeOfStackCommit;
  Self.SizeOfHeapReserve := Header32.SizeOfHeapReserve;
  Self.SizeOfHeapCommit := Header32.SizeOfHeapCommit;
  Self.LoaderFlags := Header32.LoaderFlags;
  Self.NumberOfRvaAndSizes := Header32.NumberOfDataDirectoryEntries;

  for i := Low(Header32.DataDirectory) to High(Header32.DataDirectory) do
    Self.DataDirectory[i] := Header32.DataDirectory[i];
end;

procedure TPeHeader.Assign(const Header64: TImageOptionalHeader64);
var
  i: Integer;
begin
  Self.Magic := Header64.Magic;
  Self.MajorLinkerVersion := Header64.MajorLinkerVersion;
  Self.MinorLinkerVersion := Header64.MinorLinkerVersion;
  Self.SizeOfCode := Header64.SizeOfCode;
  Self.SizeOfInitializedData := Header64.SizeOfInitializedData;
  Self.SizeOfUninitializedData := Header64.SizeOfUninitializedData;
  Self.AddressOfEntryPoint := Header64.AddressOfEntryPoint;
  Self.BaseOfCode := Header64.BaseOfCode;
  Self.ImageBase := Header64.ImageBase;
  Self.SectionAlignment := Header64.SectionAlignment;
  Self.FileAlignment := Header64.FileAlignment;
  Self.MajorOperatingSystemVersion := Header64.MajorOperatingSystemVersion;
  Self.MinorOperatingSystemVersion := Header64.MinorOperatingSystemVersion;
  Self.MajorImageVersion := Header64.MajorImageVersion;
  Self.MinorImageVersion := Header64.MinorImageVersion;
  Self.MajorSubsystemVersion := Header64.MajorSubsystemVersion;
  Self.MinorSubsystemVersion := Header64.MinorSubsystemVersion;
  Self.Win32VersionValue := Header64.Win32VersionValue;
  Self.SizeOfImage := Header64.SizeOfImage;
  Self.SizeOfHeaders := Header64.SizeOfHeaders;
  Self.CheckSum := Header64.CheckSum;
  Self.Subsystem := Header64.Subsystem;
  Self.DllCharacteristics := Header64.DllCharacteristics;
  Self.SizeOfStackReserve := Header64.SizeOfStackReserve;
  Self.SizeOfStackCommit := Header64.SizeOfStackCommit;
  Self.SizeOfHeapReserve := Header64.SizeOfHeapReserve;
  Self.SizeOfHeapCommit := Header64.SizeOfHeapCommit;
  Self.LoaderFlags := Header64.LoaderFlags;
  Self.NumberOfRvaAndSizes := Header64.NumberOfRvaAndSizes;

  for i := Low(Header64.DataDirectory) to High(Header64.DataDirectory) do
    Self.DataDirectory[i] := Header64.DataDirectory[i];
end;

end.
