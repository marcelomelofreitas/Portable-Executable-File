unit uTestarCriacaoExe;

interface

uses
  Types,
  SysUtils,
  stdio,
  cstring,
  Se7e.XED,
  Se7e.PeFile.API;

type

  TNomeImportacao = packed record
    Dica: WORD;
    Nome: AnsiString;
    OffsetDentroDaSecao: DWORD;
    EnderecoVirtualRelativo: DWORD;
    PointerToRawImportByName: DWORD;
    PointerToRawFunctionNameListItem: DWORD;
    PointerToRawFunctionAddressListItem: DWORD;
  end;

  TImportacao = packed record
    Nome: AnsiString;
    OffsetDentroDaSecao: DWORD;
    EnderecoVirtualRelativo: DWORD;
    PointerToRawImportDescriptor: NativeInt;

    PointerToRawFunctionNameList: NativeInt;
    PointerToRawFunctionAddressList: NativeInt;

    PointerToRawModuleName: NativeInt;
    Funcoes: array of TNomeImportacao;
  end;

procedure CriarExeDeTeste;

implementation

// 4x faster than dateutils version
function UnixTimeToDateTimeFast(const UnixTime: LongWord): TDateTime;
begin
  Result := (UnixTime / 86400) + 25569;
end;

// 10x faster than dateutils version
function DateTimeToUnixTimeFast(const DelphiTime : TDateTime): LongWord;
begin
  Result := Round((DelphiTime - 25569) * 86400);
end;


function AlignUp(Value: DWORD; Align: DWORD): DWORD;
var
  d, m: DWORD;
begin
  d := Value div Align;
  m := Value mod Align;
  if m = 0 then
    Result := Value
  else
    Result := (d + 1) * Align;
end;


procedure CriarExeDeTeste;
var
  DosHeader: TImageDosHeader;
  NtHeaders32: TImageNtHeaders32;
//  OptionalHeader32: TImageOptionalHeader32;
//  SectionHeader: TImageSectionHeader;
  Exe: THandle;
  Modelo: THandle;
  Res: Integer;
  Signature: LongWord;
//  FileHeader: TImageFileHeader;
//  OffsetCabecalhosOpcionais, DataDirOfs,
//  OffsetCabecalhosSecoes,
//  OffsetFimCabecalhosSecoes,
//  SecDataOfs: UInt64;
  data: TDateTime;
  SizeTest: UInt64;
//  Section: TBytes;
  ImportDescriptor: TImageImportDescriptor;
  ThunkData32: TImageThunkData32;
  ImportByName: TImageImportByName;
//  pModule: array[0..5023] of AnsiChar;

  Secoes: array of TImageSectionHeader;
  CabecalhoSecaoDeImportacoes: PImageSectionHeader;
  CabecalhoSecaoDeCodigo: PImageSectionHeader;
  SecaoDeCodigo: TBytes;
  SecaoDeImportacoes: TBytes;
  TabelaDeEnderecosDeImportacao: array of TImageThunkData32;
  TabelaDeNomesDeImportacao: array of TImageThunkData32;

  Importacoes: array of TImportacao;
  ModuloIndex: Integer;
  FuncaoIndex:  Integer;
  OffsetNomesAtual: DWORD;
  OffsetModulosAtual: DWORD;
  Dica: PWORD;
begin
{
  Modelo := fopen('a:\ver\ModeloDelphi.exe', 'r');
//  Modelo := fopen('A:\ver\Release\Win32Con.exe', 'r');
  fseek(Modelo, 0, SEEK_END);
  if ftell(Modelo) < SizeOf(DosHeader)  then
    raise Exception.Create('arquivo invalido.');

  rewind(Modelo);
  if fread(DosHeader, 1, SizeOf(DosHeader), Modelo) <> SizeOf(DosHeader) then
    raise Exception.Create('Falha na leitura de DOsHeader.');

  if DosHeader.MagicNumber <> IMAGE_DOS_SIGNATURE then
    raise Exception.Create('formato de arquivo desconhecido.');

  fSeek(Modelo, DosHeader.AddressOfPeHeader, SEEK_SET);
  if fread(Signature, 1, SizeOf(Signature), Modelo) <> SizeOf(Signature) then
    raise Exception.Create('Falha na Leitura de Signature.');

  if Signature <> IMAGE_NT_SIGNATURE then
    raise Exception.Create('formato de arquivo desconhecido.');


  if fread(FileHeader, 1, SizeOf(FileHeader), Modelo) <> SizeOf(FileHeader) then
    raise Exception.Create('Falha na Leitura de FileHeader.');

  // Obter offsets do cabeçalho opcional e dos cabeçalhos de seção.
//  OffsetCabecalhosOpcionais := ftell(Modelo);
//  OffsetCabecalhosSecoes := OffsetCabecalhosOpcionais + FileHeader.SizeOfOptionalHeader;
//  OffsetFimCabecalhosSecoes := OffsetCabecalhosSecoes + SizeOf(TImageSectionHeader) * FileHeader.NumberOfSections;


//  fseek(Modelo, OffsetCabecalhosSecoes, SEEK_SET);

//  fseek(Modelo, OffsetCabecalhosOpcionais, SEEK_SET);

  if FileHeader.Machine = IMAGE_FILE_MACHINE_I386 then
  begin
    FillChar(OptionalHeader32, SizeOf(TImageOptionalHeader32), #0);

    if fread(OptionalHeader32, 1, SizeOf(TImageOptionalHeader32), Modelo) <> SizeOf(TImageOptionalHeader32) then
      raise Exception.Create('Falha na Leitura de OptionalHeader32.');

    if OptionalHeader32.Magic <> IMAGE_NT_OPTIONAL_HDR32_MAGIC then
      raise Exception.Create('formato de arquivo desconhecido.');
  end
  else
    raise Exception.Create('tipo de arquivo não suportado.');

  Res := ftell(Modelo);

  FillChar(SectionHeader, SizeOf(TImageSectionHeader), #0);
  if fread(SectionHeader, 1, SizeOf(TImageSectionHeader), Modelo) <> SizeOf(TImageSectionHeader) then
    raise Exception.Create('Falha na Leitura de TImageSectionHeader.');

  Res := ftell(Modelo);

  FillChar(SectionHeader, SizeOf(TImageSectionHeader), #0);
  if fread(SectionHeader, 1, SizeOf(TImageSectionHeader), Modelo) <> SizeOf(TImageSectionHeader) then
    raise Exception.Create('Falha na Leitura de TImageSectionHeader.');

  fSeek(Modelo, SectionHeader.PointerToRawData, SEEK_SET);

  Res := ftell(Modelo);

  FillChar(ImportDescriptor, 20, #0);
  if fread(ImportDescriptor, 1, 20, Modelo) <> 20 then
    raise Exception.Create('Falha na Leitura de TImageImportDescriptor.');

  res := ImportDescriptor.Name - SectionHeader.VirtualAddress;

//  fSeek(Modelo, res, SEEK_CUR);

  FillChar(pModule, SizeOf(pModule), #0);
  Res := fread(pModule[0], 1, SizeOf(pModule), Modelo);

  SetLength(Section, OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
  Res := fread(Section[0], 1, Length(Section), Modelo);

  Res := ftell(Modelo);






 }

  ///Inicio do codigo de geração do exe
  FillChar(DosHeader, SizeOf(TImageDosHeader), #0);
  DosHeader.MagicNumber := IMAGE_DOS_SIGNATURE;
  DosHeader.AddressOfPeHeader := SizeOf(TImageDosHeader);

  //Prepara o código do programa
  SetLength(SecaoDeCodigo, 30);
  FillChar(SecaoDeCodigo[0], Length(SecaoDeCodigo), #0);
  SecaoDeCodigo[0] := $B8;          //mov eax, $7
  SecaoDeCodigo[1] := $00000007;
  SecaoDeCodigo[5] := $BB;          //mov ebx, $4
  SecaoDeCodigo[6] := $00000004;
  SecaoDeCodigo[10] := $29;         //add eax, ebx
  SecaoDeCodigo[11] := $D8;
  SecaoDeCodigo[12] := $C3;         //ret


  SetLength(Secoes, 2);
  FillChar(Secoes[0], SizeOf(Secoes), #0);
  CabecalhoSecaoDeCodigo := @Secoes[0];
  CabecalhoSecaoDeImportacoes := @Secoes[1];



 { ==========================================================================
                     Prepara o cabeçalho da seção de codigo
   ========================================================================== }
  FillChar(CabecalhoSecaoDeCodigo^, SizeOf(TImageSectionHeader), #0);
  CabecalhoSecaoDeCodigo.Name := '.code';
  CabecalhoSecaoDeCodigo.SizeOfRawData :=  Length(SecaoDeCodigo);


  CabecalhoSecaoDeCodigo.PointerToRelocations := 0;
  CabecalhoSecaoDeCodigo.PointerToLinenumbers := 0;
  CabecalhoSecaoDeCodigo.NumberOfRelocations := 0;
  CabecalhoSecaoDeCodigo.NumberOfLinenumbers := 0;
  CabecalhoSecaoDeCodigo.Characteristics := IMAGE_SCN_CNT_CODE +
                                            IMAGE_SCN_MEM_READ +
                                            IMAGE_SCN_MEM_EXECUTE;
  { -------------------------------------------------------------------------
                        Fim do cabeçalho da seção de codigo
    ------------------------------------------------------------------------- }





 { ==========================================================================
                  Prepara o cabeçalho da seção de importações
   ========================================================================== }
  FillChar(CabecalhoSecaoDeImportacoes^, SizeOf(TImageSectionHeader), #0);
  CabecalhoSecaoDeImportacoes.Name := '.idata';
  CabecalhoSecaoDeImportacoes.SizeOfRawData := 144;
  CabecalhoSecaoDeImportacoes.SizeOfRawData := AlignUp(144,
                                                       IMAGE_FILE_ALIGNAMENT);

  CabecalhoSecaoDeImportacoes.PointerToRawData := AlignUp(CabecalhoSecaoDeCodigo.PointerToRawData +
                                                          CabecalhoSecaoDeCodigo.SizeOfRawData,
                                                          IMAGE_FILE_ALIGNAMENT);
  CabecalhoSecaoDeImportacoes.VirtualAddress := AlignUp(CabecalhoSecaoDeImportacoes.PointerToRawData,
                                                        IMAGE_FILE_SECTION_ALIGNAMENT);
  CabecalhoSecaoDeImportacoes.VirtualSize := AlignUp(CabecalhoSecaoDeImportacoes.SizeOfRawData,
                                                     IMAGE_FILE_SECTION_ALIGNAMENT);
  CabecalhoSecaoDeImportacoes.PointerToRelocations := 0;
  CabecalhoSecaoDeImportacoes.PointerToLinenumbers := 0;
  CabecalhoSecaoDeImportacoes.NumberOfRelocations := 0;
  CabecalhoSecaoDeImportacoes.NumberOfLinenumbers := 0;
  CabecalhoSecaoDeImportacoes.Characteristics := IMAGE_SCN_CNT_INITIALIZED_DATA +
                                                 IMAGE_SCN_MEM_READ +
                                                 IMAGE_SCN_MEM_WRITE;
  { -------------------------------------------------------------------------
                   Fim do cabeçalho da seção de importações
    ------------------------------------------------------------------------- }




 { ==========================================================================
                          Prepara o seção de importações
   ========================================================================== }
  SetLength(Importacoes, 2);
  SetLength(Importacoes[0].Funcoes, 1);
  SetLength(Importacoes[1].Funcoes, 1);
  Importacoes[0].Nome := 'user32.dll';
  Importacoes[0].Funcoes[0].Nome := 'MessageBoxA';
  Importacoes[1].Nome := 'kernel32.dll';
  Importacoes[1].Funcoes[0].Nome := 'ExitProcess';

  //Prepara o código do programa
  SetLength(SecaoDeImportacoes, 1000);
  FillChar(SecaoDeImportacoes[0], Length(SecaoDeImportacoes), #0);
  FillChar(ImportDescriptor, SizeOf(TImageImportDescriptor), #0);
  FillChar(ThunkData32, SizeOf(TImageThunkData32), #0);
  SetLength(TabelaDeEnderecosDeImportacao, 0);
  SetLength(TabelaDeNomesDeImportacao, 0);

  OffsetNomesAtual := 0;

  for ModuloIndex := Low(Importacoes) to High(Importacoes) do
  begin
    strcpy(@SecaoDeImportacoes[OffsetNomesAtual], PAnsiChar(Importacoes[ModuloIndex].Nome));
    Importacoes[ModuloIndex].OffsetDentroDaSecao := OffsetNomesAtual;
    Importacoes[ModuloIndex].EnderecoVirtualRelativo := 0;
    Inc(OffsetNomesAtual, Length(Importacoes[ModuloIndex].Nome) + 2);

    for FuncaoIndex := Low(Importacoes[ModuloIndex].Funcoes) to High(Importacoes[ModuloIndex].Funcoes) do
    begin
      strcpy(@SecaoDeImportacoes[OffsetNomesAtual], PAnsiChar(Importacoes[ModuloIndex].Funcoes[FuncaoIndex].Nome));
      Importacoes[ModuloIndex].Funcoes[FuncaoIndex].OffsetDentroDaSecao := OffsetNomesAtual;
      Importacoes[ModuloIndex].Funcoes[FuncaoIndex].EnderecoVirtualRelativo := 0;
      Inc(OffsetNomesAtual, Length(Importacoes[ModuloIndex].Funcoes[FuncaoIndex].Nome) + 2);
    end;
  end;


//  ImportByName.Hint := 0;
//  ImportByName.Name := 0;

  SetLength(TabelaDeEnderecosDeImportacao, 1);
//  TabelaDeEnderecosDeImportacao[0].AddressOfData :=



  { -------------------------------------------------------------------------
                            Fim da seção de importações
    ------------------------------------------------------------------------- }


  Exe := fopen('a:\ver\teste.exe', 'w+');

  Res := fwrite(@DosHeader, 1, SizeOf(TImageDosHeader), Exe);
  if Res <> SizeOf(TImageDosHeader) then
    raise Exception.Create('Falha ao gravar o cabecalho DOS');

  FillChar(NtHeaders32, SizeOf(TImageNtHeaders32), #0);
  NtHeaders32.Signature := IMAGE_NT_SIGNATURE;
  NtHeaders32.FileHeader.Machine := IMAGE_FILE_MACHINE_I386;
  NtHeaders32.FileHeader.NumberOfSections := 2;
  NtHeaders32.FileHeader.TimeDateStamp := DateTimeToUnixTimeFast(Now());
  NtHeaders32.FileHeader.PointerToSymbolTable := 0;
  NtHeaders32.FileHeader.NumberOfSymbols := 0;
  NtHeaders32.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader32);
  NtHeaders32.FileHeader.Characteristics := IMAGE_FILE_EXECUTABLE_IMAGE +
                                            IMAGE_FILE_LINE_NUMS_STRIPPED +
                                            IMAGE_FILE_LOCAL_SYMS_STRIPPED +
                                            IMAGE_FILE_BYTES_REVERSED_LO +
                                            IMAGE_FILE_32BIT_MACHINE +
                                            IMAGE_FILE_BYTES_REVERSED_HI;
  NtHeaders32.OptionalHeader32.Magic := IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  NtHeaders32.OptionalHeader32.MajorLinkerVersion := 2;
  NtHeaders32.OptionalHeader32.MinorLinkerVersion := 25;
  NtHeaders32.OptionalHeader32.SizeOfCode := 0;
  NtHeaders32.OptionalHeader32.SizeOfInitializedData := 0;
  NtHeaders32.OptionalHeader32.SizeOfUninitializedData := 0;
  NtHeaders32.OptionalHeader32.BaseOfCode := 0;
  NtHeaders32.OptionalHeader32.BaseOfData := 0;
  NtHeaders32.OptionalHeader32.ImageBase := $400000;
  NtHeaders32.OptionalHeader32.SectionAlignment := IMAGE_FILE_SECTION_ALIGNAMENT;
  NtHeaders32.OptionalHeader32.FileAlignment := IMAGE_FILE_ALIGNAMENT;
  NtHeaders32.OptionalHeader32.MajorOperatingSystemVersion := 0;
  NtHeaders32.OptionalHeader32.MinorOperatingSystemVersion := 0;
  NtHeaders32.OptionalHeader32.MajorImageVersion := 0;
  NtHeaders32.OptionalHeader32.MinorImageVersion := 0;
  NtHeaders32.OptionalHeader32.MinorImageVersion := 0;
  NtHeaders32.OptionalHeader32.MajorSubsystemVersion := 4;
  NtHeaders32.OptionalHeader32.MinorSubsystemVersion := 0;
  NtHeaders32.OptionalHeader32.Win32VersionValue := 0;
  NtHeaders32.OptionalHeader32.SizeOfHeaders := AlignUp(DosHeader.AddressOfPeHeader +
                                                        SizeOf(TImageNtHeaders32) +
                                                        SizeOf(TImageSectionHeader) *  NtHeaders32.FileHeader.NumberOfSections,
                                                        IMAGE_FILE_ALIGNAMENT);
  NtHeaders32.OptionalHeader32.CheckSum := 0;
  NtHeaders32.OptionalHeader32.Subsystem := IMAGE_SUBSYSTEM_WINDOWS_GUI;
  NtHeaders32.OptionalHeader32.DllCharacteristics := 0;
  NtHeaders32.OptionalHeader32.SizeOfStackReserve := 0;
  NtHeaders32.OptionalHeader32.SizeOfStackCommit := $1000;
  NtHeaders32.OptionalHeader32.SizeOfHeapReserve := $100000;
  NtHeaders32.OptionalHeader32.SizeOfHeapCommit := 0;
  NtHeaders32.OptionalHeader32.LoaderFlags := 0;
  NtHeaders32.OptionalHeader32.NumberOfDataDirectoryEntries := IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  CabecalhoSecaoDeCodigo.PointerToRawData := NtHeaders32.OptionalHeader32.SizeOfHeaders;
  CabecalhoSecaoDeCodigo.VirtualAddress := AlignUp(CabecalhoSecaoDeCodigo.PointerToRawData,
                                                   IMAGE_FILE_SECTION_ALIGNAMENT);
  CabecalhoSecaoDeCodigo.VirtualSize := AlignUp(CabecalhoSecaoDeCodigo.SizeOfRawData,
                                                IMAGE_FILE_SECTION_ALIGNAMENT);

  NtHeaders32.OptionalHeader32.AddressOfEntryPoint := CabecalhoSecaoDeCodigo.VirtualAddress;

  CabecalhoSecaoDeImportacoes.PointerToRawData := AlignUp(CabecalhoSecaoDeCodigo.PointerToRawData +
                                                          CabecalhoSecaoDeCodigo.SizeOfRawData,
                                                          IMAGE_FILE_ALIGNAMENT);

  CabecalhoSecaoDeImportacoes.VirtualAddress := AlignUp(CabecalhoSecaoDeCodigo.VirtualAddress +
                                                        CabecalhoSecaoDeCodigo.VirtualSize,
                                                        IMAGE_FILE_SECTION_ALIGNAMENT);

  NtHeaders32.OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress := CabecalhoSecaoDeImportacoes.VirtualAddress;
  NtHeaders32.OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualSize := CabecalhoSecaoDeImportacoes.VirtualSize;


  NtHeaders32.OptionalHeader32.SizeOfImage := CabecalhoSecaoDeImportacoes.VirtualAddress  +
                                              CabecalhoSecaoDeImportacoes.VirtualSize;

  Res := fwrite(@NtHeaders32, 1, SizeOf(TImageNtHeaders32), Exe);
  if Res <> SizeOf(TImageNtHeaders32) then
    raise Exception.Create('Falha ao gravar o cabecalho PE');

  Res := ftell(Exe);

//
  //Gravas os cabeçalhos das seções
  Res := fwrite(CabecalhoSecaoDeCodigo, 1, SizeOf(TImageSectionHeader), Exe);
  if Res <> SizeOf(TImageSectionHeader) then
    raise Exception.Create('Falha ao gravar o cabecalho da seção de codigo');

  Res := ftell(Exe);

  Res := fwrite(CabecalhoSecaoDeImportacoes, 1, SizeOf(TImageSectionHeader), Exe);
  if Res <> SizeOf(TImageSectionHeader) then
    raise Exception.Create('Falha ao gravar o cabecalho da seção de importações');


  //Grava a seção de código
  fSeek(Exe, CabecalhoSecaoDeCodigo.PointerToRawData, SEEK_SET);
  Res := fwrite(@SecaoDeCodigo[0], 1, Length(SecaoDeCodigo), Exe);
  if Res <> Length(SecaoDeCodigo) then
    raise Exception.Create('Falha ao gravar a seção de codigo');



  {=====================================================================}
  //              GRAVAÇÃO A SEÇÃO DE IMPORTAÇÃO
  {=====================================================================}
  // Grava todos os IMAGE_IMPORT_DESCRIPTOR e salva a posição onde
  // foi gravado fisicamente no disco para mais tarde voltar e colocar o
  // endereço virtual relativo (RVA). Na primeira passagem grava tudo zero,
  // o objetivo é saber  o local/endereço (PointerToRawImportDescriptor)
  // onde foi gravado no arquivo em disco.
  // Por ultimo grava um nulo para dizer para o carregador que acabou.

  Res := ftell(Exe);

  fSeek(Exe, CabecalhoSecaoDeImportacoes.PointerToRawData, SEEK_SET);

  Res := ftell(Exe);

  for ModuloIndex := Low(Importacoes) to High(Importacoes) do
  begin
    FillChar(ImportDescriptor, SizeOf(TImageImportDescriptor), #0);
    Importacoes[ModuloIndex].PointerToRawImportDescriptor := ftell(Exe);
    Res := fwrite(@ImportDescriptor, 1, SizeOf(TImageImportDescriptor), Exe);
    if Res <> SizeOf(TImageImportDescriptor) then
      raise Exception.CreateFmt('Falha ao gravar o ImportDescriptor %d-%s', [ModuloIndex, Importacoes[ModuloIndex].Nome]);
  end;

  // Grava um com tudo nulo, para assim dizer ao carregador que os Imports
  // acabaram temos que gravar um import com tudo nil/null.
  // A estrutura de imports é um array terminado em nulo #0.
  FillChar(ImportDescriptor, SizeOf(TImageImportDescriptor), #0);
  Res := fwrite(@ImportDescriptor, 1, SizeOf(TImageImportDescriptor), Exe);
  if Res <> SizeOf(TImageImportDescriptor) then
    raise Exception.CreateFmt('Falha ao gravar o TImageImportDescriptor %d-%s', [ModuloIndex, Importacoes[ModuloIndex].Nome]);



  // grava a primeira tabela para lista de nomes
  // Grava um IMAGE_THUNK_DATA32 para cada modulo e salva
  // o local/endereco (PointerToRawFunctionNameList) onde
  // foi gravado para mais tarde voltar colocar o Endereço Virtual Relativo (RVA)
  for ModuloIndex := Low(Importacoes) to High(Importacoes) do
  begin
    Importacoes[ModuloIndex].PointerToRawFunctionNameList := ftell(Exe);

    for FuncaoIndex := Low(Importacoes[ModuloIndex].Funcoes) to High(Importacoes[ModuloIndex].Funcoes) do
    begin
      Importacoes[ModuloIndex].Funcoes[FuncaoIndex].PointerToRawFunctionNameListItem := ftell(Exe);

      FillChar(ThunkData32, SizeOf(TImageThunkData32), #0);
      Res := fwrite(@ThunkData32, 1, SizeOf(TImageThunkData32), Exe);
      if Res <> SizeOf(TImageThunkData32) then
        raise Exception.CreateFmt('Falha ao gravar o TImageThunkData32 %d-%s', [ModuloIndex, Importacoes[ModuloIndex].Nome]);
    end;

    // Grava um IMAGE_THUNK_DATA32 com tudo nulo, para assim dizer ao carregador
    // que os Nomes do Import acabaram e para isso temos que
    // gravar um IMAGE_THUNK_DATA32 com tudo nil/null.
    FillChar(ThunkData32, SizeOf(TImageThunkData32), #0);
    Res := fwrite(@ThunkData32, 1, SizeOf(TImageThunkData32), Exe);
    if Res <> SizeOf(TImageThunkData32) then
      raise Exception.Create('Falha ao gravar o TImageThunkData32 nulo de final do array');
  end;


  // grava a tabela duplicada para lista de  endereco
  // Grava um IMAGE_THUNK_DATA32 para cada modulo e salva
  // o local/endereco (PointerToRawFunctionAddressList) onde
  // foi gravado para mais tarde voltar colocar o Endereço Virtual Relativo (RVA)
  for ModuloIndex := Low(Importacoes) to High(Importacoes) do
  begin
    Importacoes[ModuloIndex].PointerToRawFunctionAddressList := ftell(Exe);

    for FuncaoIndex := Low(Importacoes[ModuloIndex].Funcoes) to High(Importacoes[ModuloIndex].Funcoes) do
    begin
      Importacoes[ModuloIndex].Funcoes[FuncaoIndex].PointerToRawFunctionAddressListItem := ftell(Exe);

      FillChar(ThunkData32, SizeOf(TImageThunkData32), #0);
      Res := fwrite(@ThunkData32, 1, SizeOf(TImageThunkData32), Exe);
      if Res <> SizeOf(TImageThunkData32) then
        raise Exception.CreateFmt('Falha ao gravar o TImageThunkData32 %d-%s', [ModuloIndex, Importacoes[ModuloIndex].Nome]);
    end;

    // Grava um IMAGE_THUNK_DATA32 com tudo nulo, para assim dizer ao carregador
    // que os Nomes do Import acabaram e para isso temos que
    // gravar um IMAGE_THUNK_DATA32 com tudo nil/null.
    FillChar(ThunkData32, SizeOf(TImageThunkData32), #0);
    Res := fwrite(@ThunkData32, 1, SizeOf(TImageThunkData32), Exe);
    if Res <> SizeOf(TImageThunkData32) then
      raise Exception.Create('Falha ao gravar o TImageThunkData32 nulo de final do array');
  end;


  // Grava um IMAGE_IMPORT_BY_NAME para cada funcao e salva
  // o local/endereco (PointerToRawImportByName) onde
  // foi gravado para mais tarde voltar colocar o Endereço Virtual Relativo (RVA).
  for ModuloIndex := Low(Importacoes) to High(Importacoes) do
  begin
    Importacoes[ModuloIndex].PointerToRawModuleName := ftell(Exe);

    Res := fwrite(@Importacoes[ModuloIndex].Nome[1], 1, Length(Importacoes[ModuloIndex].Nome) + 1, Exe);
    if Res <> (Length(Importacoes[ModuloIndex].Nome) + 1) then
      raise Exception.CreateFmt('Falha ao gravar o ModuleName para/do ImportDescriptor %d-%s', [ModuloIndex, Importacoes[ModuloIndex].Nome]);

    fwrite($0, 1, 1, Exe);

    for FuncaoIndex := Low(Importacoes[ModuloIndex].Funcoes) to High(Importacoes[ModuloIndex].Funcoes) do
    begin
      Importacoes[ModuloIndex].Funcoes[FuncaoIndex].PointerToRawImportByName := ftell(Exe);

      Dica := @Importacoes[ModuloIndex].Funcoes[FuncaoIndex].Dica;

      Res := fwrite(Dica, 1, SizeOf(Importacoes[ModuloIndex].Funcoes[FuncaoIndex].Dica), Exe);
      if Res <> SizeOf(Importacoes[ModuloIndex].Funcoes[FuncaoIndex].Dica) then
        raise Exception.CreateFmt('Falha ao gravar o TImageImportByName.Hint %d-%s', [ModuloIndex, Importacoes[ModuloIndex].Nome]);

      Res := fwrite(PUtf8Char(Importacoes[ModuloIndex].Funcoes[FuncaoIndex].Nome), 1, Length(Importacoes[ModuloIndex].Funcoes[FuncaoIndex].Nome) + 1, Exe);
      if Res <> (Length(Importacoes[ModuloIndex].Funcoes[FuncaoIndex].Nome) + 1) then
        raise Exception.CreateFmt('Falha ao gravar o TImageImportByName.Hint %d-%s', [ModuloIndex, Importacoes[ModuloIndex].Nome]);

      fwrite($0, 1, 1, Exe);
    end;
  end;

  fwrite($0, 1, 1, Exe);
  CabecalhoSecaoDeImportacoes.SizeOfRawData := ftell(Exe) - CabecalhoSecaoDeImportacoes.PointerToRawData;

  // Agora calcula e grava todos os RVA (Endereço Virtual Relativo)
  for ModuloIndex := Low(Importacoes) to High(Importacoes) do
  begin
    fSeek(Exe, Importacoes[ModuloIndex].PointerToRawImportDescriptor, SEEK_SET);
    Res := fread(ImportDescriptor, 1, SizeOf(TImageImportDescriptor), Exe);
    if Res <> SizeOf(TImageImportDescriptor) then
      raise Exception.CreateFmt('Falha ao ler o ImportDescriptor %d-%s ao para calcular/salvar os endereços virtuais dos imports', [ModuloIndex, Importacoes[ModuloIndex].Nome]);

    ImportDescriptor.RVAFunctionNameList := CabecalhoSecaoDeImportacoes.VirtualAddress + (Importacoes[ModuloIndex].PointerToRawFunctionNameList - CabecalhoSecaoDeImportacoes.PointerToRawData);
    ImportDescriptor.RVAModuleName := CabecalhoSecaoDeImportacoes.VirtualAddress + (importacoes[ModuloIndex].PointerToRawModuleName - CabecalhoSecaoDeImportacoes.PointerToRawData);
    ImportDescriptor.RVAFunctionAddressList := CabecalhoSecaoDeImportacoes.VirtualAddress + (Importacoes[ModuloIndex].PointerToRawFunctionAddressList - CabecalhoSecaoDeImportacoes.PointerToRawData);

    fSeek(Exe, Importacoes[ModuloIndex].PointerToRawImportDescriptor, SEEK_SET);
    Res := fwrite(@ImportDescriptor, 1, SizeOf(TImageImportDescriptor), Exe);
    if Res <> SizeOf(TImageImportDescriptor) then
      raise Exception.CreateFmt('Falha ao gravar o ImportDescriptor %d-%s depois de calcular a RVA', [ModuloIndex, Importacoes[ModuloIndex].Nome]);

    for FuncaoIndex := Low(Importacoes[ModuloIndex].Funcoes) to High(Importacoes[ModuloIndex].Funcoes) do
    begin
      //Calcula e salva o RVA para ThunkData32
      fSeek(Exe, Importacoes[ModuloIndex].Funcoes[FuncaoIndex].PointerToRawFunctionNameListItem, SEEK_SET);
      Res := fread(ThunkData32, 1, SizeOf(TImageThunkData32), Exe);
      if Res <> SizeOf(TImageThunkData32) then
        raise Exception.CreateFmt('Falha ao ler o TImageThunkData32 %d-%s ao para calcular/salvar os endereços virtuais dos imports', [ModuloIndex, Importacoes[ModuloIndex].Nome]);

      ThunkData32.AddressOfData := CabecalhoSecaoDeImportacoes.VirtualAddress + (Importacoes[ModuloIndex].Funcoes[FuncaoIndex].PointerToRawImportByName - CabecalhoSecaoDeImportacoes.PointerToRawData);

      fSeek(Exe, Importacoes[ModuloIndex].Funcoes[FuncaoIndex].PointerToRawFunctionNameListItem, SEEK_SET);
      Res := fwrite(@ThunkData32, 1, SizeOf(TImageThunkData32), Exe);
      if Res <> SizeOf(TImageThunkData32) then
        raise Exception.CreateFmt('Falha ao gravar o TImageThunkData32 %d-%s apos ter calculado seu RVA', [ModuloIndex, Importacoes[ModuloIndex].Nome]);







       //segunda tabela
      //Calcula e salva o RVA para ThunkData32
      fSeek(Exe, Importacoes[ModuloIndex].Funcoes[FuncaoIndex].PointerToRawFunctionAddressListItem, SEEK_SET);
      Res := fread(ThunkData32, 1, SizeOf(TImageThunkData32), Exe);
      if Res <> SizeOf(TImageThunkData32) then
        raise Exception.CreateFmt('Falha ao ler o TImageThunkData32 %d-%s ao para calcular/salvar os endereços virtuais dos imports', [ModuloIndex, Importacoes[ModuloIndex].Nome]);

      ThunkData32.AddressOfData := CabecalhoSecaoDeImportacoes.VirtualAddress + (Importacoes[ModuloIndex].Funcoes[FuncaoIndex].PointerToRawImportByName - CabecalhoSecaoDeImportacoes.PointerToRawData);

      fSeek(Exe, Importacoes[ModuloIndex].Funcoes[FuncaoIndex].PointerToRawFunctionAddressListItem, SEEK_SET);
      Res := fwrite(@ThunkData32, 1, SizeOf(TImageThunkData32), Exe);
      if Res <> SizeOf(TImageThunkData32) then
        raise Exception.CreateFmt('Falha ao gravar o TImageThunkData32 %d-%s apos ter calculado seu RVA', [ModuloIndex, Importacoes[ModuloIndex].Nome]);
    end;
  end;

  CabecalhoSecaoDeImportacoes.VirtualSize := AlignUp(CabecalhoSecaoDeImportacoes.SizeOfRawData,
                                                     IMAGE_FILE_SECTION_ALIGNAMENT);
  NtHeaders32.OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress := CabecalhoSecaoDeImportacoes.VirtualAddress;
  NtHeaders32.OptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualSize := CabecalhoSecaoDeImportacoes.VirtualSize;

  NtHeaders32.OptionalHeader32.SizeOfImage := CabecalhoSecaoDeImportacoes.VirtualAddress  +
                                              CabecalhoSecaoDeImportacoes.VirtualSize;


  //grava todos os cabecalhos
  fSeek(Exe, 0, SEEK_SET);

  Res := fwrite(@DosHeader, 1, SizeOf(TImageDosHeader), Exe);
  if Res <> SizeOf(TImageDosHeader) then
    raise Exception.Create('Falha ao gravar o cabecalho DOS');

  Res := fwrite(@NtHeaders32, 1, SizeOf(TImageNtHeaders32), Exe);
  if Res <> SizeOf(TImageNtHeaders32) then
    raise Exception.Create('Falha ao gravar o cabecalho PE');

  Res := ftell(Exe);

//
  //Gravas os cabeçalhos das seções
  Res := fwrite(CabecalhoSecaoDeCodigo, 1, SizeOf(TImageSectionHeader), Exe);
  if Res <> SizeOf(TImageSectionHeader) then
    raise Exception.Create('Falha ao gravar o cabecalho da seção de codigo');

  Res := ftell(Exe);

  Res := fwrite(CabecalhoSecaoDeImportacoes, 1, SizeOf(TImageSectionHeader), Exe);
  if Res <> SizeOf(TImageSectionHeader) then
    raise Exception.Create('Falha ao gravar o cabecalho da seção de importações');

  FillChar(SecaoDeCodigo[0], Length(SecaoDeCodigo), #0);
  SecaoDeCodigo[0] := $6A;          //push 0
  SecaoDeCodigo[1] := $00;          //
  SecaoDeCodigo[2] := $6A;          //push 0
  SecaoDeCodigo[3] := $00;          //
  SecaoDeCodigo[4] := $6A;          //push 0
  SecaoDeCodigo[5] := $00;          //
  SecaoDeCodigo[6] := $6A;          //push 0
  SecaoDeCodigo[7] := $00;          //

  SecaoDeCodigo[8] := $B8;          //mov eax, ...
  PCardinal(@SecaoDeCodigo[9])^ := NtHeaders32.OptionalHeader32.ImageBase +  CabecalhoSecaoDeImportacoes.VirtualAddress + (Importacoes[0].Funcoes[0].PointerToRawFunctionAddressListItem - CabecalhoSecaoDeImportacoes.PointerToRawData);

  SecaoDeCodigo[13] := $FF;          //call eax
  SecaoDeCodigo[14] := $D0;          //

  SecaoDeCodigo[15] := $C3;         //ret

  //Grava a seção de código
  fSeek(Exe, CabecalhoSecaoDeCodigo.PointerToRawData, SEEK_SET);
  Res := fwrite(@SecaoDeCodigo[0], 1, Length(SecaoDeCodigo), Exe);
  if Res <> Length(SecaoDeCodigo) then
    raise Exception.Create('Falha ao gravar a seção de codigo');

  //Fim :)
  fclose(Exe);
end;

end.
