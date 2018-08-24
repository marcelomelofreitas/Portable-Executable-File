program PEFileTest;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  stdio,
  Se7e.PeFile.API in 'Se7e.PeFile.API.pas',
  Se7e.PeFile in 'Se7e.PeFile.pas',
  uTestarCriacaoExe in 'uTestarCriacaoExe.pas',
  Se7e.XED in 'Se7e.XED.pas',
  Se7e.AsmEncoder in 'Se7e.AsmEncoder.pas';

procedure dump(d: string);
begin
  printf(PChar(d));
  printf(^J);
end;

function centerOutput(const txt: string; const maxsize: Integer = 70): string;
var
  left: Integer;
begin
  left := Trunc((maxsize - Length(txt)) / 2);
  Result := txt.PadLeft(left);
end;

function formatOutput(text: string; val: string; pad: string = ''; maxsize: Integer = 70): string;
begin
  Result := pad + text + StringOfChar(' ', maxsize - Length(text) - Length(val) - Length(pad));
  Result := Result + val;
end;


procedure dumpMzHeader(PeFile: TPeFile);
var
  MzHeader: TPeMzHeader;
  DOSMagic: array[0..1] of AnsiChar absolute MzHeader;
  i: Integer;
begin
  MzHeader := PeFile.PeMzHeader;

  dump(centerOutput('MZ Header'));
  dump(formatOutput('e_magic', String(DOSMagic)));
	dump(formatOutput('e_cblp', IntToStr(MzHeader.BytesOnLastPage)));
	dump(formatOutput('e_cp', IntToStr(MzHeader.PagesInFile)));
	dump(formatOutput('e_crlc', IntToStr(MzHeader.Relocations)));
	dump(formatOutput('e_cparhdr', IntToStr(MzHeader.SizeOfHeader)));
	dump(formatOutput('e_minalloc', IntToStr(MzHeader.MinExtraParagraphs)));
	dump(formatOutput('e_maxalloc', IntToStr(MzHeader.MaxExtraParagraphs)));
	dump(formatOutput('e_ss', IntToStr(MzHeader.InitialStackSegment)));
	dump(formatOutput('e_sp', IntToStr(MzHeader.InitialStackPointer)));
	dump(formatOutput('e_csum', IntToStr(MzHeader.Checksum)));
	dump(formatOutput('e_ip', IntToStr(MzHeader.InitialInstructionPointer)));
	dump(formatOutput('e_cs', IntToStr(MzHeader.InitialCodeSegment)));
	dump(formatOutput('e_lfarlc', IntToStr(MzHeader.AddressOfRelocationTable)));
	dump(formatOutput('e_ovnovalue', IntToStr(MzHeader.OverlayNumber)));

  for i := Low(MzHeader.ReservedWords1) to High(MzHeader.ReservedWords1) do
    dump(formatOutput('e_res', AnsiChar((MzHeader.ReservedWords1[i]))));

	dump(formatOutput('e_oemid', IntToStr(MzHeader.OemIdentifier)));
	dump(formatOutput('e_oeminfo', IntToStr(MzHeader.OemInformation)));

  for i := Low(MzHeader.ReservedWords2) to High(MzHeader.ReservedWords2) do
    dump(formatOutput('e_res2', AnsiChar((MzHeader.ReservedWords2[i]))));

	dump(formatOutput('e_lfanew', IntToStr(MzHeader.AddressOfPeHeader)));

	dump('');
	dump(centerOutput('----------------------------------------------'));
	dump('');

end;


type
// struct for memory view window
  TMemView = record
    HFile: THandle;
    MMFile: THandle;
    Mem: Pointer;
    Base: DWORD;
    Size: DWORD;
    xWin, yWin: DWORD;
    PosV, RangeV: DWORD;
    Lines: NativeInt;
    ExtraBytes: DWORD;
  end;

var
  PeFile: TPeFile;
  sh: TImageSectionHeader;
  oh: TImageOptionalHeader32;
  fh: TImageFileHeader;
  MemView: TMemView;
  ofs: TOFStruct;
  Header: TImageFileHeader;
  OptionalHeader32: TImageOptionalHeader32;
  DosHeader: TImageDosHeader;
  Test: AnsiString;
begin
  CriarExeDeTeste();
  exit;

  FillChar(MemView, Sizeof(MemView), #0);


//  MemView.hFile := windows.OpenFile('A:\x64dbg\release\x32\x32dbg.exe', ofs, OF_READ);
  MemView.hFile := windows.OpenFile('a:\teste.exe', ofs, OF_READ);

  if MemView.hFile = 0 then
    raise Exception.Create('falha ao abrir o arquivo');

  MemView.Size := GetFileSize(MemView.HFile, nil);
  MemView.Base := 0;

  MemView.MMFile := windows.CreateFileMapping(MemView.hFile, nil, PAGE_READONLY, 0, 0, nil);

  if MemView.MMFile = 0 then
    raise Exception.Create('falha ao criar o mapa do arquivo');


  MemView.Mem := MapViewOfFile(MemView.MMFile, FILE_MAP_WRITE, 0, 0, 0);

  if (MemView.Mem = nil) then
    raise Exception.Create('falha ao mapear o arquivo');



  case ImageFileType(MemView.Mem) of
    IMAGE_NT_SIGNATURE: Writeln('NT Image - ');
    IMAGE_DOS_SIGNATURE: Writeln('DOS Image - ');
  else
    Writeln('Outros');
  end;

  if not GetPeFileHeader(MemView.Mem, @Header) then
    raise Exception.Create('Error Message: GetPeFileHeader');

  if not GetPeOptionalHeader32(MemView.Mem, @OptionalHeader32) then
    raise Exception.Create('Error Message GetPeOptionalHeader32');

  if not GetPeSectionHeaderByName(MemView.Mem, @sh, '.data') then
    raise Exception.Create('Error Message GetPeSectionHeaderByName');

  GetPeNumberOfExportedFunctions(MemView.Mem);

  GetPeDosHeader(MemView.Mem, @DosHeader);

//  GetPeExportFunctionNames(MemView.Mem, GetProcessHeap(), &szTest);


//  PeFile := OpenPeFile('A:\x64dbg\release\x64\x64dbg.exe');
//  PeFile := OpenPeFile('A:\x64dbg\release\x32\x32dbg.exe');
//  dumpMzHeader(PeFile);

//''.PadLeft(7);



end.
