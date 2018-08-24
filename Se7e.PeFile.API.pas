unit Se7e.PeFile.API;

interface

uses
  cstring,
  Types;

type
  LPSTR = MarshaledAString;
  LPWSTR = PWideChar;

  MakeIntResourceA = LPSTR;
  MakeIntResourceW = LPWSTR;
  MakeIntResource = MakeIntResourceW;

const
  SIZE_OF_NT_SIGNATURE = sizeof(DWORD);

//Predefined Resource Types
  RT_CURSOR       = MakeIntResource(1);
  RT_BITMAP       = MakeIntResource(2);
  RT_ICON         = MakeIntResource(3);
  RT_MENU         = MakeIntResource(4);
  RT_DIALOG       = MakeIntResource(5);
  RT_STRING       = MakeIntResource(6);
  RT_FONTDIR      = MakeIntResource(7);
  RT_FONT         = MakeIntResource(8);
  RT_ACCELERATOR  = MakeIntResource(9);
  RT_RCDATA       = MakeIntResource(10);
  RT_MESSAGETABLE = MakeIntResource(11);

// Debug Types
  IMAGE_DEBUG_TYPE_UNKNOWN          = 00;
  IMAGE_DEBUG_TYPE_COFF             = 01;
  IMAGE_DEBUG_TYPE_CODEVIEW         = 02;
  IMAGE_DEBUG_TYPE_FPO              = 03;
  IMAGE_DEBUG_TYPE_MISC             = 04;
  IMAGE_DEBUG_TYPE_EXCEPTION        = 05;
  IMAGE_DEBUG_TYPE_FIXUP            = 06;
  IMAGE_DEBUG_TYPE_OMAP_TO_SRC      = 07;
  IMAGE_DEBUG_TYPE_OMAP_FROM_SRC    = 08;
  IMAGE_DEBUG_TYPE_BORLAND          = 09;
  IMAGE_DEBUG_TYPE_RESERVED10       = 10;
  IMAGE_DEBUG_TYPE_CLSID            = 11;
  IMAGE_DEBUG_TYPE_VC_FEATURE       = 12;
  IMAGE_DEBUG_TYPE_POGO             = 13;
  IMAGE_DEBUG_TYPE_ILTCG            = 14;
  IMAGE_DEBUG_TYPE_MPX              = 15;
  IMAGE_DEBUG_TYPE_REPRO            = 16;

// Directory Entries
  IMAGE_DIRECTORY_ENTRY_EXPORT             = 00;  { Diretório de Exportação }
  IMAGE_DIRECTORY_ENTRY_IMPORT             = 01;  { Diretório de Importação }
  IMAGE_DIRECTORY_ENTRY_RESOURCE           = 02;  { Diretório de Recursos }
  IMAGE_DIRECTORY_ENTRY_EXCEPTION          = 03;  { Diretório de exceção }
  IMAGE_DIRECTORY_ENTRY_SECURITY           = 04;  { Diretório de segurança }
  IMAGE_DIRECTORY_ENTRY_BASERELOC          = 05;  { Tabela de Relocação de Base }
  IMAGE_DIRECTORY_ENTRY_DEBUG              = 06;  { Diretório de Depuração }
  IMAGE_DIRECTORY_ENTRY_ARCHITECTURE       = 07;  { Dados Específicos de Arquitetura }
  IMAGE_DIRECTORY_ENTRY_GLOBALPTR          = 08;  { Valor da Máquina (RVA de GP) }
  IMAGE_DIRECTORY_ENTRY_TLS                = 09;  { Diretório TLS }
  IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG        = 10;  { Diretório Carregar Configuração }
  IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT       = 11;  { Diretório de importação vinculado em cabeçalhos }
  IMAGE_DIRECTORY_ENTRY_IAT                = 12;  { tabela de endereços de importação }
  IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT       = 13;  { Diretorio de importação atrasado }
  IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR     = 14;  { Descritor de tempo de execução COM }
  IMAGE_NUMBEROF_DIRECTORY_ENTRIES         = 16;


  IMAGE_SIZEOF_SHORT_NAME                  = 08;

// Image Format
  IMAGE_DOS_SIGNATURE                      = $5A4D;      { MZ }
  IMAGE_OS2_SIGNATURE                      = $454E;      { NE }
  IMAGE_OS2_SIGNATURE_LE                   = $454C;      { LE }
  IMAGE_VXD_SIGNATURE                      = $454C;      { LE }
  IMAGE_NT_SIGNATURE                       = $4550;      { PE00 }
  IMAGE_NT_OPTIONAL_HDR32_MAGIC            = $010b;
  IMAGE_NT_OPTIONAL_HDR64_MAGIC            = $020b;
  IMAGE_ROM_OPTIONAL_HDR_MAGIC             = $0107;

  IMAGE_FILE_SECTION_ALIGNAMENT            = 4096;
  IMAGE_FILE_ALIGNAMENT                    = 512;

  IMAGE_SIZEOF_FILE_HEADER                 = 00020;

// File header format.
  IMAGE_FILE_RELOCS_STRIPPED               = $0001;  // Relocation info stripped from file.
  IMAGE_FILE_EXECUTABLE_IMAGE              = $0002;  // File is executable  (i.e. no unresolved external references).
  IMAGE_FILE_LINE_NUMS_STRIPPED            = $0004;  // Line nunbers stripped from file.
  IMAGE_FILE_LOCAL_SYMS_STRIPPED           = $0008;  // Local symbols stripped from file.
  IMAGE_FILE_AGGRESIVE_WS_TRIM             = $0010;  // Aggressively trim working set
  IMAGE_FILE_LARGE_ADDRESS_AWARE           = $0020;  // App can handle >2gb addresses
  IMAGE_FILE_BYTES_REVERSED_LO             = $0080;  // Bytes of machine WORD are reversed.
  IMAGE_FILE_32BIT_MACHINE                 = $0100;  // 32 bit WORD machine.
  IMAGE_FILE_DEBUG_STRIPPED                = $0200;  // Debugging info stripped from file in .DBG file
  IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP       = $0400;  // If Image is on removable media, copy and run from the swap file.
  IMAGE_FILE_NET_RUN_FROM_SWAP             = $0800;  // If Image is on Net, copy and run from the swap file.
  IMAGE_FILE_SYSTEM                        = $1000;  // System File.
  IMAGE_FILE_DLL                           = $2000;  // File is a DLL.
  IMAGE_FILE_UP_SYSTEM_ONLY                = $4000;  // File should only be run on a UP machine
  IMAGE_FILE_BYTES_REVERSED_HI             = $8000;  // Bytes of machine WORD are reversed.

  IMAGE_FILE_MACHINE_UNKNOWN               = $0000;
  IMAGE_FILE_MACHINE_TARGET_HOST           = $0001;  // Useful for indicating we want to interact with the host and not a WoW guest.
  IMAGE_FILE_MACHINE_I386                  = $014c;  // Intel 386.
  IMAGE_FILE_MACHINE_R3000                 = $0162;  // MIPS little-endian, $160 big-endian
  IMAGE_FILE_MACHINE_R4000                 = $0166;  // MIPS little-endian
  IMAGE_FILE_MACHINE_R10000                = $0168;  // MIPS little-endian
  IMAGE_FILE_MACHINE_WCEMIPSV2             = $0169;  // MIPS little-endian WCE v2
  IMAGE_FILE_MACHINE_ALPHA                 = $0184;  // Alpha_AXP
  IMAGE_FILE_MACHINE_SH3                   = $01a2;  // SH3 little-endian
  IMAGE_FILE_MACHINE_SH3DSP                = $01a3;
  IMAGE_FILE_MACHINE_SH3E                  = $01a4;  // SH3E little-endian
  IMAGE_FILE_MACHINE_SH4                   = $01a6;  // SH4 little-endian
  IMAGE_FILE_MACHINE_SH5                   = $01a8;  // SH5
  IMAGE_FILE_MACHINE_ARM                   = $01c0;  // ARM Little-Endian
  IMAGE_FILE_MACHINE_THUMB                 = $01c2;  // ARM Thumb/Thumb-2 Little-Endian
  IMAGE_FILE_MACHINE_ARMNT                 = $01c4;  // ARM Thumb-2 Little-Endian
  IMAGE_FILE_MACHINE_AM33                  = $01d3;
  IMAGE_FILE_MACHINE_POWERPC               = $01F0;  // IBM PowerPC Little-Endian
  IMAGE_FILE_MACHINE_POWERPCFP             = $01f1;
  IMAGE_FILE_MACHINE_IA64                  = $0200;  // Intel 64
  IMAGE_FILE_MACHINE_MIPS16                = $0266;  // MIPS
  IMAGE_FILE_MACHINE_ALPHA64               = $0284;  // ALPHA64
  IMAGE_FILE_MACHINE_MIPSFPU               = $0366;  // MIPS
  IMAGE_FILE_MACHINE_MIPSFPU16             = $0466;  // MIPS
  IMAGE_FILE_MACHINE_AXP64                 = IMAGE_FILE_MACHINE_ALPHA64;
  IMAGE_FILE_MACHINE_TRICORE               = $0520;  // Infineon
  IMAGE_FILE_MACHINE_CEF                   = $0CEF;
  IMAGE_FILE_MACHINE_EBC                   = $0EBC;  // EFI Byte Code
  IMAGE_FILE_MACHINE_AMD64                 = $8664;  // AMD64 (K8)
  IMAGE_FILE_MACHINE_M32R                  = $9041;  // M32R little-endian
  IMAGE_FILE_MACHINE_ARM64                 = $AA64;  // ARM64 Little-Endian
  IMAGE_FILE_MACHINE_CEE                   = $C0EE;

// Subsystem Values
  IMAGE_SUBSYSTEM_UNKNOWN                  = 00;   // Subsistema desconhecido.
  IMAGE_SUBSYSTEM_NATIVE                   = 01;   // Nenhum subsistema necessário (drivers de dispositivo e processos nativos do sistema).
  IMAGE_SUBSYSTEM_WINDOWS_GUI              = 02;   // Subsistema de interface gráfica de usuário do Windows (GUI).
  IMAGE_SUBSYSTEM_WINDOWS_CUI              = 03;   // Subsistema de interface de usuário (CUI) do modo de caracteres do Windows.
  IMAGE_SUBSYSTEM_OS2_CUI                  = 05;   // Subsistema CUI do OS / 2.
  IMAGE_SUBSYSTEM_POSIX_CUI                = 07;   // Subsistema POSIX CUI.
  IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 08;   // image is a native Win9x driver.
  IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 09;   // Sistema Windows CE.
  IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10;   // Aplicação Extensible Firmware Interface (EFI).
  IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11;   // Driver EFI com serviços de inicialização.
  IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12;   // Driver EFI com serviços de tempo de execução.
  IMAGE_SUBSYSTEM_EFI_ROM                  = 13;   // Imagem da ROM EFI.
  IMAGE_SUBSYSTEM_XBOX                     = 14;   // Sistema Xbox.
  IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16;   // Aplicação de inicialização.
  IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG        = 17;

// Section characteristics.
  IMAGE_SCN_CNT_CODE                   = $00000020;  // A seção contém código executável.
  IMAGE_SCN_CNT_INITIALIZED_DATA       = $00000040;  // A seção contém dados inicializados.
  IMAGE_SCN_CNT_UNINITIALIZED_DATA     = $00000080;  // A seção contém dados não inicializados.
  IMAGE_SCN_LNK_INFO                   = $00000200;  // A seção contém comentários ou outras informações. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_LNK_REMOVE                 = $00000800;  // A seção não se tornará parte da imagem. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_LNK_COMDAT                 = $00001000;  // A seção contém dados do COMDAT. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_NO_DEFER_SPEC_EXC          = $00004000;  // Redefina as exceções especulativas que manipulam bits nas entradas de TLB para esta seção.
  IMAGE_SCN_GPREL                      = $00008000;  // A seção contém dados referenciados através do ponteiro global.
  IMAGE_SCN_MEM_FARDATA                = $00008000;
  IMAGE_SCN_MEM_PURGEABLE              = $00020000;
  IMAGE_SCN_MEM_16BIT                  = $00020000;
  IMAGE_SCN_MEM_LOCKED                 = $00040000;
  IMAGE_SCN_MEM_PRELOAD                = $00080000;
  IMAGE_SCN_ALIGN_1BYTES               = $00100000;  // Alinhar dados em um limite de 1 byte. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_2BYTES               = $00200000;  // Alinhar dados em um limite de 2 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_4BYTES               = $00300000;  // Alinhar dados em um limite de 4 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_8BYTES               = $00400000;  // Alinhar dados em um limite de 8 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_16BYTES              = $00500000;  // Alinhar dados em um limite de 16 bytes. Isso é válido apenas para arquivos de objeto
  IMAGE_SCN_ALIGN_32BYTES              = $00600000;  // Alinhar dados em um limite de 32 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_64BYTES              = $00700000;  // Alinhar dados em um limite de 64 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_128BYTES             = $00800000;  // Alinhar dados em um limite de 128 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_256BYTES             = $00900000;  // Alinhar dados em um limite de 256 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_512BYTES             = $00A00000;  // Alinhar dados em um limite de 512 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_1024BYTES            = $00B00000;  // Alinhar dados em um limite de 1024 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_2048BYTES            = $00C00000;  // Alinhar dados em um limite de 2048 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_4096BYTES            = $00D00000;  // Alinhar dados em um limite de 4096 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_8192BYTES            = $00E00000;  // Alinhar dados em um limite de 8192 bytes. Isso é válido apenas para arquivos de objeto.
  IMAGE_SCN_ALIGN_MASK                 = $00F00000;
  IMAGE_SCN_LNK_NRELOC_OVFL            = $01000000;  // Section contains extended relocations.
  IMAGE_SCN_MEM_DISCARDABLE            = $02000000;  // Section can be discarded.
  IMAGE_SCN_MEM_NOT_CACHED             = $04000000;  // Section is not cachable.
  IMAGE_SCN_MEM_NOT_PAGED              = $08000000;  // Section is not pageable.
  IMAGE_SCN_MEM_SHARED                 = $10000000;  // Section is shareable.
  IMAGE_SCN_MEM_EXECUTE                = $20000000;  // Section is executable.
  IMAGE_SCN_MEM_READ                   = $40000000;  // Section is readable.
  IMAGE_SCN_MEM_WRITE                  = $80000000;  // Section is writeable.


type

  ULONGLONG = UInt64;

{ Cabeçalho do DOS -> IMAGE_DOS_HEADER - 64 bytes
  ===============================================
  Todos os arquivos PE começam com o cabeçalho DOS, que ocupa os primeiros 64 bytes do arquivo. Ele está lá, caso o
  programa seja executado a partir do DOS, para que o DOS possa reconhecê-lo como um executável válido e executar o
  stub do DOS que é armazenado imediatamente após o cabeçalho. O stub DOS geralmente apenas imprime uma string
  como "Este programa deve ser executado no Microsoft Windows", mas pode ser um programa DOS completo. Ao criar
  um aplicativo para o Windows, o vinculador vincula um programa stub padrão chamado WINSTUB.EXE ao executável.
  Você pode substituir o comportamento do vinculador padrão substituindo seu próprio programa baseado em MS-DOS
  válido no lugar de WINSTUB e usando a opção -STUB: vinculador ao vincular o arquivo executável.}
  PImageDosHeader = ^TImageDosHeader;
  TImageDosHeader = packed record                  { Cabeçalho .EXE do DOS                                     }
  {00} MagicNumber: WORD;                          { e_magic - Número mágico (MZ)                              }
  {02} BytesOnLastPage: WORD;                      { e_cblp - Bytes na última página do arquivo                }
  {04} PagesInFile: WORD;                          { e_cp - Páginas no arquivo                                 }
  {06} Relocations: WORD;                          { e_crlc - Realocações                                      }
  {08} SizeOfHeader: WORD;                         { e_cparhdr - Tamanho do cabeçalho nos parágrafos           }
  {0A} MinExtraParagraphs: WORD;                   { e_minalloc - Parâmetros mínimos extras necessários        }
  {0C} MaxExtraParagraphs: WORD;                   { e_maxalloc - Máximo de parágrafos extras necessários      }
  {0E} InitialStackSegment: WORD;                  { e_ss - Segmento de pilha inicial                          }
  {10} InitialStackPointer: WORD;                  { e_sp - Ponteiro de Pilha Inicial                          }
  {12} Checksum: WORD;                             { e_csum - Checksum                                         }
  {14} InitialInstructionPointer: WORD;            { e_ip - Ponteiro de instrução inicial                      }
  {16} InitialCodeSegment: WORD;                   { e_cs - Segmento de código inicial                         }
  {18} AddressOfRelocationTable: WORD;             { e_lfarlc - Endereço de arquivo da tabela de realocação    }
  {1A} OverlayNumber: WORD;                        { e_ovno - Número de sobreposição                           }
  {1C} ReservedWords1: array[0..3] of WORD;        { e_res - Palavras reservadas                               }
  {24} OemIdentifier: WORD;                        { e_oemid - Identificador OEM (para e_oeminfo)              }
  {26} OemInformation: WORD;                       { e_oeminfo - Informação do OEM; e_oemid específico         }
  {28} ReservedWords2: array[0..9] of WORD;        { e_res2 - Palavras reservadas                              }
  {3C} AddressOfPeHeader: DWORD;                   { e_lfanew - Endereço do arquivo do novo cabeçalho exe      }
  end;

{ Cabeçalho PE -> IMAGE_FILE_HEADER
  =================================
  Representa o formato do cabeçalho COFF.}
  PImageFileHeader = ^TImageFileHeader;
  TImageFileHeader = packed record
    Machine: WORD;                                 { O tipo de arquitetura do computador.
                                                     Um arquivo de imagem só pode ser executado no computador especificado
                                                     ou em um sistema que emula o computador especificado. }

    NumberOfSections: WORD;                        { O número de seções. Isso indica o tamanho da tabela de seções,
                                                     que segue imediatamente os cabeçalhos.
                                                     Observe que o carregador do Windows limita o número de seções a 96. }

    TimeDateStamp: DWORD;                          { Os 32 bits baixos do registro de data e hora da imagem.
                                                     Isso representa a data e a hora em que a imagem foi criada pelo
                                                     vinculador. O valor é representado no número de segundos decorridos
                                                     desde a meia-noite (00:00:00), 1º de janeiro de 1970,
                                                     Tempo Universal Coordenado, de acordo com o relógio do sistema. }

    PointerToSymbolTable: DWORD;                   { O deslocamento da tabela de símbolos, em bytes,
                                                     ou zero, se não existir nenhuma tabela de símbolos COFF. }

    NumberOfSymbols: DWORD;                        { O número de símbolos na tabela de símbolos. }

    SizeOfOptionalHeader: WORD;                    { O tamanho do cabeçalho opcional, em bytes.
                                                     Esse valor deve ser 0 para arquivos de objeto. }

    Characteristics: WORD;                         { As características da imagem.
                                                     Esse membro pode ser um ou mais valores.
                                                     Exemplo:
                                                              IMAGE_FILE_EXECUTABLE_IMAGE,
                                                              IMAGE_FILE_DLL,
                                                              IMAGE_FILE_32BIT_MACHINE,
                                                              IMAGE_FILE_SYSTEM,
                                                              etc..}
  end;

{ Formato de diretório -> IMAGE_DATA_DIRECTORY
  ============================================ }
  PImageDataDirectory = ^TImageDataDirectory;
  TImageDataDirectory = packed record
    VirtualAddress: DWORD;  // O endereço virtual relativo da tabela.
    VirtualSize: DWORD;            // O tamanho da tabela, em bytes.
  end;

{ Formato do cabeçalho opcional para 32 bits -> IMAGE_OPTIONAL_HEADER32
  =====================================================================
  O cabeçalho opcional contém a maioria das informações significativas sobre o
  imagem executável, como tamanho da pilha inicial, localização do ponto de entrada do programa,
  endereço base preferido, versão do sistema operacional, alinhamento de seção
  informação, e assim por diante }
  PImageOptionalHeader32 = ^TImageOptionalHeader32;
  TImageOptionalHeader32 = packed record
    //
    // Campos padrão
    // =============
    // Os campos padrão são aqueles comuns ao Objeto Comum File Format (COFF),
    // que a maioria dos arquivos executáveis do UNIX usa. Embora os campos padrão
    // use os nomes definidos no COFF, o Windows NT, na verdade, usa alguns deles
    // para diferentes propósitos que seriam melhor descritos com outros nomes.

    Magic: WORD;                                { O estado do arquivo de imagem. Esse membro pode ser
                                                  um dos seguintes valores. IMAGE_NT_OPTIONAL_HDR32_MAGIC,
                                                  IMAGE_NT_OPTIONAL_HDR64_MAGIC ou IMAGE_ROM_OPTIONAL_HDR_MAGIC. }

    MajorLinkerVersion: BYTE;                   // Indica a versão do vinculador que ligava essa imagem.
                                                // O desenvolvimento preliminar de software do Windows NT Kit (SDK),
                                                // fornecido com compilar 438 do Windows NT, inclui vinculador versão = $2.27

    MinorLinkerVersion: BYTE;                   // Mesmo que acima
    SizeOfCode: DWORD;                          // Tamanho do código executável.
    SizeOfInitializedData: DWORD;               // Tamanho dos dados inicializados.
    SizeOfUninitializedData: DWORD;             // Tamanho dos dados não inicializados.
    AddressOfEntryPoint: DWORD;                 // Indica o localização do ponto de entrada para a aplicação.
    BaseOfCode: DWORD;                          // Deslocamento relativo do código (seção ".text") na imagem carregada.
    BaseOfData: DWORD;                          // Deslocamento relativo de dados não inicializados (seção ".bss")
                                                // na imagem carregada.

    //
    // Campos Adicionais do Windows NT
    // ===============================
    // Os campos adicionais adicionados ao formato de arquivo PE do Windows NT fornecem suporte  a
    // carregador para grande parte do comportamento de processo específico do Windows NT

    ImageBase: DWORD;                           // Endereço base "preferencial" no espaço de endereço de um processo para
                                                // mapear a imagem executável para. O padrão é = $00400000, mas você pode
                                                // substituir se preferir.

    SectionAlignment: DWORD;                    // Cada seção é carregada no espaço de endereço de um processo
                                                // sequencialmente, começando no ImageBase. O SectionAlignment dita a
                                                // quantidade mínima de espaço que uma seção pode ocupar quando
                                                // carregada, isto é, as seções são alinhadas nos limites de SectionAlignment.
                                                // O alinhamento de seção não pode ser menor que o tamanho da página
                                                // (atualmente 4096 bytes na plataforma x86) e deve ser um múltiplo do
                                                // tamanho da página conforme ditado pelo comportamento do gerenciador
                                                // de memória virtual do Windows NT. Esse valor deve ser maior ou igual ao
                                                // membro FileAlignment. O valor padrão é o tamanho da página do sistema.

    FileAlignment: DWORD;                       // Granularidade mínima de pedaços de informação dentro do
                                                // arquivo de imagem antes do carregamento. Por exemplo, o linker zera uma
                                                // seção corpo (dados brutos para uma seção) até o limite FileAlignment
                                                // mais próximo o arquivo. A versão = $2.27 do linker fornecido com
                                                // compilar 438 do Windows NT alinha arquivos de imagem em uma granularidade
                                                // de = $200 bytes. Este valor é restrito para ser uma potência de 2
                                                // entre 512 e 65.535. Se o membro SectionAlignment for menor que o
                                                // tamanho de página do sistema, esse membro deverá ser o mesmo que SectionAlignment.

    MajorOperatingSystemVersion: WORD;          // Indica a versão principal do Windows Sistema operacional NT,
                                                // atualmente definido como 1 para o Windows NT versão 1.0.

    MinorOperatingSystemVersion: WORD;          // Indica a versão secundária do Windows NT sistema operacional,
                                                // atualmente definido como 0 para o Windows NT versão 1.0.

    MajorImageVersion: WORD;                    // Usado para indicar o número da versão principal da
                                                // aplicação; no Microsoft Excel versão 4.0, seria 4.

    MinorImageVersion: WORD;                    // Usado para indicar o número da versão secundária do
                                                // aplicação; no Microsoft Excel versão 4.0, seria 0.

    MajorSubsystemVersion: WORD;                // Indica o subsistema principal do Windows NT Win32
                                                // número de versão, atualmente definido como 3 para
                                                // o Windows NT versão 3.10.

    MinorSubsystemVersion: WORD;                // Indica o menor subsistema Windows NT Win32
                                                // número de versão, atualmente definido como 10
                                                // para o Windows NT versão 3.10.

    Win32VersionValue: DWORD;                   // Este membro é reservado e deve ser 0.

    SizeOfImage: DWORD;                         // Indica a quantidade de espaço de endereço a ser reservado no
                                                // espaço de endereço para a imagem executável carregada.
                                                // Esse número é influenciado e muito pelo SectionAlignment.
                                                // Por exemplo, considere um sistema com um tamanho de página de 4096 bytes.
                                                // Se você tiver um executável com 11 seções, cada uma com menos de 4096 bytes,
                                                // alinhados em um limite de 65.536 bytes, o campo SizeOfImage
                                                // seria definido para 11 * 65.536 = 720.896 (176 páginas).
                                                // O mesmo arquivo vinculado ao alinhamento de 4096 bytes
                                                // resultaria em 11 * 4096 = 45.056 (11 páginas) para o campo SizeOfImage.
                                                // Este é um exemplo simples em que cada seção requer menos de uma
                                                // página de memória. Na realidade, o linker determina o SizeOfImage
                                                // exato, calculando cada seção individualmente. isto primeiro
                                                // determina quantos bytes a seção requer, então arredonda para
                                                // limite da página mais próxima e, finalmente, arredonda a
                                                // contagem de páginas para o mais próximo Limite de SectionAlignment.
                                                // O total é então a soma de cada seção exigência individual.

    SizeOfHeaders: DWORD;                       // O tamanho arredondado para um múltiplo do valor especificado no membro
                                                // FileAlignment com o resultado da soma dos itens a seguir:
                                                //   1) e_lfanew membro de IMAGE_DOS_HEADER
                                                //   2) Assinatura de 4 bytes
                                                //   3) Tamanho de IMAGE_FILE_HEADER
                                                //   4) Tamanho do cabeçalho opcional
                                                //   5) Tamanho de todos os cabeçalhos de seção


    CheckSum: DWORD;                            // O valor CheckSum é usado para validar o imagem no momento do carregamento.
                                                // Os seguintes arquivos são validados no tempo de carregamento:
                                                // Todos os drivers, qualquer DLL carregada no momento da inicialização e
                                                // qualquer DLL carregada em um processo crítico do sistema.

    Subsystem: WORD;                            // O subsistema necessário para executar esta imagem.
                                                // Exemplo:
                                                //         IMAGE_SUBSYSTEM_NATIVE,
                                                //         IMAGE_SUBSYSTEM_WINDOWS_GUI,
                                                //         IMAGE_SUBSYSTEM_WINDOWS_CUI,
                                                //         etc

    DllCharacteristics: WORD;                   // Sinalizadores usados para indicar se uma imagem DLL inclui pontos
                                                // de entrada para inicialização e finalização de processos e segmentos.

    SizeOfStackReserve: DWORD;                  // SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit.
                                                // Esses campos controlam a quantidade de espaço de endereço para
                                                // reservar e confirmar a pilha e a pilha padrão. Tanto a pilha como o heap
                                                // tem valores padrão de 1 página confirmada e 16 páginas reservadas. Estes
                                                // os valores são definidos com as opções do vinculado.
    SizeOfStackCommit: DWORD;                   // O número de bytes para confirmar para a pilha.

    SizeOfHeapReserve: DWORD;                   // O número de bytes a serem reservados para o heap local.
                                                // Apenas a memória especificada pelo membro SizeOfHeapCommit é
                                                // confirmada no tempo de carregamento;
                                                // o restante é disponibilizado uma página por vez até que esse
                                                // tamanho de reserva seja atingido.

    SizeOfHeapCommit: DWORD;                    // O número de bytes para confirmar para o heap local.

    LoaderFlags: DWORD;                         // Este membro é obsoleto.

    NumberOfDataDirectoryEntries: DWORD;        // Este campo identifica o comprimento do array DataDirectory a seguir.
                                                // É importante notar que este campo é usado para identificar o tamanho
                                                // da matriz, não o número de entradas válidas na array.


    // O diretório de dados (DataDirectory) indica onde encontrar outros
    // componentes de informações executáveis no arquivo. Realmente não é nada
    // mais do que uma matriz de estruturas IMAGE_DATA_DIRECTORY localizadas em
    // o final da estrutura do cabeçalho opcional. O formato de arquivo atual do PE
    // define 16 diretórios de dados possíveis.
    DataDirectory: packed array[0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES-1] of TImageDataDirectory;
  end;

{ TImageNtHeaders32 -> IMAGE_NT_HEADERS32
  =======================================
  Representa o formato do cabeçalho PE.}
  PImageNtHeaders32 = ^TImageNtHeaders32;
  TImageNtHeaders32 = packed record
    Signature: DWORD;                        { Uma assinatura de 4 bytes identificando o arquivo como uma imagem PE.
                                               Os bytes são "PE00". }

    FileHeader: TImageFileHeader;            { Uma estrutura IMAGE_FILE_HEADER que
                                               especifica o cabeçalho do arquivo. }

    OptionalHeader32: TImageOptionalHeader32;  { Uma estrutura IMAGE_OPTIONAL_HEADER32 que especifica o
                                               cabeçalho do arquivo opcional. }
  end;

{ Formato 64 bits de cabeçalho opcional -> IMAGE_OPTIONAL_HEADER64
  ================================================================ }
  PImageOptionalHeader64 = ^TImageOptionalHeader64;
  TImageOptionalHeader64 = packed record
    Magic: WORD;
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
    MajorOperatingSystemVersion: WORD;
    MinorOperatingSystemVersion: WORD;
    MajorImageVersion: WORD;
    MinorImageVersion: WORD;
    MajorSubsystemVersion: WORD;
    MinorSubsystemVersion: WORD;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: WORD;
    DllCharacteristics: WORD;
    SizeOfStackReserve: ULONGLONG;
    SizeOfStackCommit: ULONGLONG;
    SizeOfHeapReserve: ULONGLONG;
    SizeOfHeapCommit: ULONGLONG;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: packed array[0..IMAGE_NUMBEROF_DIRECTORY_ENTRIES-1] of TImageDataDirectory;
  end;

{ TImageNtHeaders64 -> IMAGE_NT_HEADERS64
  ======================================= }
  PImageNtHeaders64 = ^TImageNtHeaders64;
  TImageNtHeaders64 = packed record
    Signature: DWORD;
    FileHeader: TImageFileHeader;
    OptionalHeader: TImageOptionalHeader64;
  end;

{ A Tabela de Seção -> IMAGE_SECTION_HEADER
  ========================================
  Isto segue imediatamente após o cabeçalho PE. É uma matriz de estruturas IMAGE_SECTION_HEADER, cada uma
  contendo as informações sobre uma seção no arquivo PE, como seu atributo e deslocamento virtual. Lembre-se de que
  o número de seções é o segundo membro do FileHeader (6 bytes desde o início do cabeçalho PE). Se houver 8 seções
  no arquivo PE, haverá 8 duplicatas dessa estrutura na tabela. Cada estrutura de cabeçalho tem 40 bytes cada e não há
  "preenchimento" entre eles.}
  PImageSectionHeader = ^TImageSectionHeader;
  TImageSectionHeader = packed record
    Name: packed array[0..IMAGE_SIZEOF_SHORT_NAME-1] of UTF8Char;   { Uma string UTF-8 de 8 bytes, preenchida com nulo.
                                                                      Não há nenhum caractere nulo de terminação se a cadeia
                                                                      tiver exatamente oito caracteres. Para nomes mais longos,
                                                                      esse membro contém uma barra (/) seguida por uma representação
                                                                      ASCII de um número decimal que é um deslocamento na
                                                                      tabela de cadeias. Imagens executáveis não usam uma
                                                                      tabela de strings e não suportam nomes de seção
                                                                      com mais de oito caracteres. }

    VirtualSize: DWORD;                              { O tamanho total da seção quando carregado na memória, em bytes.
                                                                      Se esse valor for maior que o membro SizeOfRawData, a seção será
                                                                      preenchida com zeros. Este campo é válido apenas para imagens
                                                                      executáveis e deve ser definido como 0 para arquivos de objeto. }

    VirtualAddress: DWORD;             { Explicação1:
                                         ============
                                         O RVA (Relative Virtual Address) da seção.
                                         O carregador PE examina e usa o valor nesse campo ao mapear a seção na memória.
                                         Assim, se o valor neste campo for 1000h e o arquivo PE for carregado em 400000h,
                                         a seção será carregada em 401000h.

                                         Explicação2:
                                         ============
                                         Este campo identifica o endereço virtual no processo
                                         espaço de endereçamento para o qual carregar a seção. O endereço real é criado
                                         tomando o valor deste campo e adicionando-o ao ImageBase virtual
                                         endereço na estrutura do cabeçalho opcional. Tenha em mente, porém, que se
                                         este arquivo de imagem representa uma DLL, não há garantia de que a DLL
                                         ser carregado para o local do ImageBase solicitado.
                                         Então, quando o arquivo for carregado em um processo, o valor real do
                                         ImageBase deve ser verificado programaticamente usando GetModuleHandle. }

    SizeOfRawData: DWORD;                { Explicação1:
                                           ============
                                           O tamanho dos dados da seção no arquivo em disco,
                                           arredondado para o próximo múltiplo de alinhamento de arquivos pelo compilador.

                                           Explicação2:
                                           ============
                                           Este campo indica o tamanho relativo do FileAlignment do
                                           corpo da seção. O tamanho real do corpo da seção será menor que ou
                                           igual a um múltiplo de FileAlignment no arquivo. Depois que a imagem é carregada
                                           no espaço de endereço de um processo, o tamanho do corpo da seção se torna menor
                                           igual ou igual a um múltiplo de SectionAlignment. }

    PointerToRawData: DWORD;              { (Raw Offset) - incrivelmente útil porque é o deslocamento
                                            desde o início do arquivo até os dados da seção.
                                            Se for 0, os dados da seção não estão contidos no arquivo e
                                            serão arbitrários no momento do carregamento.
                                            O carregador PE usa o valor nesse campo para localizar
                                            onde os dados da seção estão no arquivo. }

    PointerToRelocations: DWORD;          // Não é usado no formato de arquivo PE.
    PointerToLinenumbers: DWORD;          // Não é usado no formato de arquivo PE.
    NumberOfRelocations: WORD;            // Não é usado no formato de arquivo PE.
    NumberOfLinenumbers: WORD;            // Não é usado no formato de arquivo PE.
    Characteristics: DWORD;               { Define as características da seção com sinalizadores, como se esta seção
                                            contém código executável, dados inicializados,
                                            dados não inicializados, se pode ser gravada ou lida, etc.. }
  end;


{ A Seção de Exportação -> IMAGE_EXPORT_DIRECTORY
  ===============================================
  As estruturas IMAGE_EXPORT_DIRECTORY apontam para três matrizes e uma tabela de cadeias ASCII. A matriz
  importante é o EAT, que é uma matriz de ponteiros de função que contém os endereços das funções exportadas. As
  outras duas matrizes (ENT & EOT) são executadas paralelas em ordem crescente com base no nome da função, de
  modo que uma pesquisa binária para o nome de uma função possa ser executada e resultará em seu ordinal sendo
  encontrado na outra matriz. O ordinal é simplesmente um índice no EAT para essa função.}
  PImageExportDirectory = ^TImageExportDirectory;
  TImageExportDirectory = packed record
      Characteristics: DWORD;
      TimeDateStamp: DWORD;
      MajorVersion: WORD;
      MinorVersion: WORD;
      Name: DWORD;                       { O nome interno do módulo. Este campo é necessário porque o
                                           nome do arquivo pode ser alterado pelo usuário.
                                           Se isso acontecer, o carregador PE usará esse nome interno. }

      Base: DWORD;                       { Iniciando o número ordinal (necessário para
                                           obter os índices no array de endereço de função). }

      NumberOfFunctions: DWORD;          { Número total de funções (também conhecidas como símbolos)
                                           que são exportadas por este módulo. }

      NumberOfNames: DWORD;              { Número de símbolos exportados por nome.
                                           Este valor não é o número de todas as funções/símbolos no módulo.
                                           Para esse número, você precisa verificar NumberOfFunctions.
                                           Pode ser 0. Nesse caso, o módulo pode exportar apenas por ordinal.
                                           Se não houver função / símbolo a ser exportado no primeiro caso,
                                           o RVA (Relative Virtual Address) da tabela de exportação no
                                           diretório de dados será 0. }

      AddressOfFunctions: DWORD;         { EAT -> Um RVA (Relative Virtual Address) que aponta para uma matriz de
                                           ponteiros para (RVAs) das funções no módulo - a Export Address Table (EAT).
                                           Em outras palavras, os RVAs para todas as funções no módulo são
                                           mantidos em uma matriz e esse campo aponta para a cabeça dessa matriz. }

      AddressOfNames: DWORD;             { ENT -> Um RVA (Relative Virtual Address) que aponta para uma matriz
                                           de RVAs dos nomes das funções no módulo - a Export Name Table (ENT). }

      AddressOfNameOrdinals: DWORD;      { EOT -> Um RVA (Relative Virtual Address) que aponta para uma matriz de
                                           de 16 bits que contém os ordinais das funções nomeadas - a Export Ordinal Table. }
  end;


{ TImageImportDescriptor -> IMAGE_IMPORT_DESCRIPTOR
  ================================================= }
  PImageImportDescriptor = ^TImageImportDescriptor;
  TImageImportDescriptor = packed record
    RVAFunctionNameList: DWORD;               { é um endereço virtual relativo a uma lista de endereços (OriginalFirstName)
                                                virtuais relativos que apontam para os nomes das funções no arquivo }
    TimeDateStamp: DWORD;             // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    ForwarderChain: DWORD;            // -1 if no forwarders
    RVAModuleName: DWORD;                    { Um endereço virtual relativo que aponta para o nome do módulo }
    RVAFunctionAddressList: DWORD;
  end;

{ TImageThunkData32 -> IMAGE_THUNK_DATA32
  ======================================= }
  TImageThunkData32 = packed record
    case Byte of
      0: (ForwarderString: DWORD); // PBYTE
      1: (_Function: DWORD);       // PDWORD Function -> _Function
      2: (Ordinal: DWORD);
      3: (AddressOfData: DWORD);   // PIMAGE_IMPORT_BY_NAME
  end;

{ TImageThunkData64 -> IMAGE_THUNK_DATA64
  ======================================= }
  TImageThunkData64 = packed record
  case Byte of
    0: (ForwarderString: ULONGLONG); // PBYTE
    1: (_Function: ULONGLONG);       // PDWORD Function -> _Function
    2: (Ordinal: ULONGLONG);
    3: (AddressOfData: ULONGLONG);   // PIMAGE_IMPORT_BY_NAME
  end;

{ TImageImportByName -> IMAGE_IMPORT_BY_NAME
  ========================================== }
  PImageImportByName = ^TImageImportByName;
  TImageImportByName = packed record
    Hint: WORD;                         { Contém o índice para a tabela de exportação Endereço do
                                          DLL a função reside em Este campo é para uso pelo carregador de
                                          PE para que ele possa olhar para cima a função na tabela de
                                          endereços de Exportação do DLL rapidamente.
                                          O nome nesse índice é testado e, se não corresponder, será
                                          feita uma pesquisa binária para localizar o nome. Como tal, esse
                                          valor não é essencial e alguns linkers definem esse campo como 0 }
    Name: array[0..0] of BYTE;          { contém o nome da função importada. O nome é uma cadeia ASCII terminada por caractere nulo. Observe que o tamanho do Name1 é definido como um byte, mas é realmente um campo de tamanho variável. É só que não há como representar um campo de tamanho variável em uma estrutura. A estrutura é fornecida para que você possa se referir a ela com nomes descritivos. }
  end;

{ TImageBoundImportDescriptor -> IMAGE_BOUND_IMPORT_DESCRIPTOR
  ============================================================ }
  PImageBoundImportDescriptor = ^TImageBoundImportDescriptor;
  TImageBoundImportDescriptor = packed record
    TimeDateStamp: DWORD;
    OffsetModuleName: WORD;
    NumberOfModuleForwarderRefs: WORD;
    // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
  end;

{ TImageBoundForwarderRef -> IMAGE_BOUND_FORWARDER_REF
  ==================================================== }
  PImageBoundForwarderRef = ^TImageBoundForwarderRef;
  TImageBoundForwarderRef = packed record
    TimeDateStamp: DWORD;
    OffsetModuleName: WORD;
    Reserved: WORD;
  end;

{ TImageResourceDirectory -> IMAGE_RESOURCE_DIRECTORY
  ====================================================
  Olhando para a estrutura de diretórios de recursos, você não encontrará nenhum ponteiro para o próximo
  nós. Em vez disso, existem dois campos, NumberOfNamedEntries e NumberOfIdEntries,
  usado para indicar quantas entradas estão anexadas ao diretório. Por anexo, quer dizer
  que as entradas do diretório seguem imediatamente após o diretório nos dados da seção.
  As entradas nomeadas aparecem primeiro em ordem crescente ordem alfabética, seguida pelas
  entradas de ID em ordem numérica crescente. }
  TImageResourceDirectory = packed record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: WORD;
    MinorVersion: WORD;
    NumberOfNamedEntries: WORD;
    NumberOfIdEntries: WORD;
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
 end;

{ TImageResourceDirectoryEntry -> IMAGE_RESOURCE_DIRECTORY_ENTRY
  ==============================================================
 Uma entrada de diretório de recurso consiste em dois campos.
 Os dois campos são usados para coisas diferentes, dependendo do nível da
 árvore. O campo Nome é usado para identificar um tipo de recurso, um recurso
 nome ou ID de idioma de um recurso. O campo OffsetToData é sempre usado para
 aponte para um irmão na árvore, um nó de diretório ou um nó de folha.
 Nós de folha são o nó mais baixo na árvore de recursos. Eles definem o tamanho e
 localização dos dados reais do recurso. Cada nó da folha é representado usando a
 estrutura IMAGE_RESOURCE_DATA_ENTRY. }
  TImageResourceDirectoryEntry = packed record
    case Integer of
      0: (
        // DWORD NameOffset:31;
        // DWORD NameIsString:1;
        NameOffset: DWORD;
        OffsetToData: DWORD
      );
      1: (
        Name: DWORD;
        // DWORD OffsetToDirectory:31;
        // DWORD DataIsDirectory:1;
        OffsetToDirectory: DWORD;
      );
      2: (
        Id: WORD;
      );
  end;

{ TImageResourceDirectoryString -> IMAGE_RESOURCE_DIRECTORY_STRING }
  TImageResourceDirectoryString = packed record
    Length: WORD;
    NameString: array[0..0] of AnsiCHAR;
  end;

{ TImageResourceDataEntry -> IMAGE_RESOURCE_DATA_ENTRY
  ====================================================
  Os dois campos OffsetToData e Size indicam a localização e o
  tamanho dos dados reais do recurso. Como essa informação é usada principalmente por
  funções depois que o aplicativo foi carregado, faz mais sentido tornar o campo
  OffsetToData um endereço virtual relativo. Este é precisamente o caso.
  Curiosamente, todos os outros deslocamentos, como ponteiros de entradas de diretório
  para outros diretórios, são deslocamentos em relação ao local do nó raiz. }
  TImageResourceDataEntry = packed record
    OffsetToData: DWORD;
    Size: DWORD;
    CodePage: DWORD;
    Reserved: DWORD;
  end;

{ TImageResourceDirStringU -> IMAGE_RESOURCE_DIR_STRING_U }
  TImageResourceDirStringU = packed record
    Length: Word;
    NameString: array[0..0] of WideChar;
  end;

{ TImageImportModuleDirectory -> IMAGE_IMPORT_MODULE_DIRECTORY
  ============================================================
  Embora um diretório IMAGE_DIRECTORY_ENTRY_IMPORT esteja definido, nenhuma estrutura de diretório
  de importação correspondente é incluída no arquivo WINNT.H. Em vez disso, existem várias outras estruturas
  chamadas IMAGE_IMPORT_BY_NAME, IMAGE_THUNK_DATA e IMAGE_IMPORT_DESCRIPTOR. Pessoalmente, eu não
  conseguia entender como essas estruturas deveriam se correlacionar com a seção .idata, então passei várias horas
  decifrando o corpo da seção .idata e encontrei uma estrutura muito mais simples. Eu nomeei essa estrutura como
  IMAGE_IMPORT_MODULE_DIRECTORY.
  Ao contrário dos diretórios de dados de outras seções, este se repete um após o outro para cada módulo importado no
  arquivo. Pense nisso como uma entrada em uma lista de diretórios de dados do módulo, em vez de um diretório de
  dados para toda a seção de dados. Cada entrada é um diretório para as informações de importação de um módulo
  específico.}
  TImageImportModuleDirectory = packed record
    RVAFunctionNameList: DWORD;               { é um endereço virtual relativo a uma lista de endereços
                                                virtuais relativos que apontam para os nomes das funções no arquivo }

    Useless1: DWORD;                          { Useless1 e Useless2 servem como preenchimento para manter a
                                                estrutura alinhada corretamente dentro da seção. }
    Useless2: DWORD;
    RVAModuleName: DWORD ;                    { Um endereço virtual relativo que aponta para o nome do módulo }
    RVAFunctionAddressList: DWORD;
  end;

{ TImageDebugDirectory -> IMAGE_DEBUG_DIRECTORY }
  PImageDebugDirectory = ^TImageDebugDirectory;
  TImageDebugDirectory = packed record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    Type_: DWORD;
    SizeOfData: DWORD;
    AddressOfRawData: DWORD;
    PointerToRawData: DWORD;
  end;

  // copia as informações do cabeçalho para a estrutura
  function GetPeDosHeader(MapFilePtr: Pointer; HeaderPtr: PImageDosHeader): Boolean;

  // definições globais para definir offsets de cabeçalho em arquivo
  // deslocamento para assinatura de arquivo PE
  function GetPeFileSignaturePtr(MapFilePtr: Pointer): Pointer;

  // retornar assinatura do arquivo
  function ImageFileType(MapFilePtr: Pointer): DWORD;

  // Copiar informações do cabeçalho do arquivo para a estrutura PImageFileHeader
  function GetPeFileHeader(MapFilePtr: Pointer; HeaderPtr: PImageFileHeader): Boolean;

  // Cabeçalho do DOS identifica a assinatura dword do NT PEFile
  // o cabeçalho PE existe logo após o dword
  function GetPeFileHeaderPtr(MapFilePtr: Pointer): Pointer;

  // Cabeçalho opcional PE é imediatamente após o cabeçalho PE
  function GetPeFileOptionalHeaderPtr(MapFilePtr: Pointer): Pointer;

  // copiar informações de cabeçalho opcionais para a estrutura
  function GetPeOptionalHeader32(MapFilePtr: Pointer; OptionalHeader32Ptr: PImageOptionalHeader32): Boolean;

  // obtém o cabeçalho da função para uma seção identificada pelo nome
  function GetPeSectionHeaderByName(MapFilePtr: Pointer; SectionHeaderPtr: PImageSectionHeader; const SectionName: AnsiString): Boolean;

  // cabeçalhos de seção são imediatamente após cabeçalho opcional PE
  function GetPeSectionHeader32Ptr(MapFilePtr: Pointer): Pointer;

  // retorna o número total de seções no arquivo PE
  function GetPeNumberOfSections(MapFilePtr: Pointer): WORD;

  // retorna o número de funções exportadas no arquivo PE
  function GetPeNumberOfExportedFunctions(MapFilePtr: Pointer): Integer;

  // retorna offset para entrada IMAGE_DIRECTORY especificada
  function ImageDirectoryOffset(MapFilePtr: Pointer; ImageDirectory: DWORD): Pointer;

implementation

function GetPeFileOptionalHeaderPtr(MapFilePtr: Pointer): Pointer;
begin
  Result := Pointer(NativeUInt(MapFilePtr) +
                    PImageDosHeader(MapFilePtr)^.AddressOfPeHeader +
                    SIZE_OF_NT_SIGNATURE +
                    SizeOf(TImageFileHeader));
end;

function GetPeFileSignaturePtr(MapFilePtr: Pointer): Pointer;
begin
  Result := Pointer(NativeUInt(MapFilePtr) +
                    PImageDosHeader(MapFilePtr)^.AddressOfPeHeader);
end;

function GetPeFileHeaderPtr(MapFilePtr: Pointer): Pointer;
begin
  Result := Pointer(NativeUInt(MapFilePtr) +
                    PImageDosHeader(MapFilePtr)^.AddressOfPeHeader +
                    SIZE_OF_NT_SIGNATURE);
end;

function GetPeSectionHeader32Ptr(MapFilePtr: Pointer): Pointer;
begin
  Result := Pointer(NativeUInt(MapFilePtr) +
                    PImageDosHeader(MapFilePtr)^.AddressOfPeHeader +
                    SIZE_OF_NT_SIGNATURE +
                    SizeOf(TImageFileHeader) +
                    SizeOf(TImageOptionalHeader32));
end;


function ImageFileType(MapFilePtr: Pointer): DWORD;
var
  Signature: DWORD;
begin
    // DOS assinatura de arquivo vem em primeiro lugar
    if Word(MapFilePtr^) = IMAGE_DOS_SIGNATURE then
    begin
      Signature := DWORD(GetPeFileSignaturePtr(MapFilePtr)^);

      //* determinar a localização do cabeçalho do arquivo PE do cabeçalho do dos
      if (Signature = IMAGE_OS2_SIGNATURE) or (Signature = IMAGE_OS2_SIGNATURE_LE) then
          Result := Signature
      else if Signature = IMAGE_NT_SIGNATURE then
          Result := IMAGE_NT_SIGNATURE
      else
          Result := IMAGE_DOS_SIGNATURE;
    end
    else
      Result := 0; // Tipo de arquivo desconhecido

end;

function GetPeFileHeader(MapFilePtr: Pointer; HeaderPtr: PImageFileHeader): Boolean;
begin

  // O cabeçalho PE segue o cabeçalho DOS
  if (ImageFileType(MapFilePtr) = IMAGE_NT_SIGNATURE) then
  begin
    Move(GetPeFileHeaderPtr(MapFilePtr)^, HeaderPtr^, SizeOf(TImageFileHeader));
    Result := True;
  end
  else
    Result := False;

end;

function GetPeOptionalHeader32(MapFilePtr: Pointer; OptionalHeader32Ptr: PImageOptionalHeader32): Boolean;
begin
  // o cabeçalho opcional segue o cabeçalho PE e o cabeçalho DOS
  if (ImageFileType(MapFilePtr) = IMAGE_NT_SIGNATURE) then
  begin
    Move(GetPeFileOptionalHeaderPtr(MapFilePtr)^, OptionalHeader32Ptr^, SizeOf(TImageOptionalHeader32));
    Result := True;
  end
  else
    Result := False;
end;

function GetPeSectionHeaderByName(MapFilePtr: Pointer; SectionHeaderPtr: PImageSectionHeader; const SectionName: AnsiString): Boolean;
var
  psh: PImageSectionHeader;
  NroSections: Integer;
  i: Integer;
begin
  NroSections := GetPeNumberOfSections(MapFilePtr);
  psh := GetPeSectionHeader32Ptr(MapFilePtr);

  if not (psh = nil) then
  begin
    // encontrar a seção pelo nome
    for i := 0 to NroSections - 1 do
    begin
      if strcmp(psh^.Name, SectionName) = 0 then
      begin
        // copiar dados para o cabeçalho
        Move(psh^, SectionHeaderPtr^, sizeof(TImageSectionHeader));
        Result := True;
        Break;
      end
      else
        inc(psh);
    end;
  end
  else
    Result := False;
end;

function GetPeNumberOfSections(MapFilePtr: Pointer): WORD;
begin
  // número de seções é indicado no cabeçalho do arquivo
  Result :=  PImageFileHeader(GetPeFileHeaderPtr(MapFilePtr))^.NumberOfSections;
end;

function GetPeNumberOfExportedFunctions(MapFilePtr: Pointer): Integer;
var
 ped: PImageExportDirectory;
begin
  // obtém o cabeçalho da seção e o ponteiro para o diretório de dados para a seção .edata
  ped := ImageDirectoryOffset(MapFilePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);

  if ped = nil then
    Result := 0
  else
    Result := ped.NumberOfNames;
end;

function ImageDirectoryOffset(MapFilePtr: Pointer; ImageDirectory: DWORD): Pointer;
var
  poh: PImageOptionalHeader32;
  psh: PImageSectionHeader;
  nSections: Integer;
  i: Integer;
  VAImageDir: DWORD;
begin
  poh := PImageOptionalHeader32(GetPeFileOptionalHeaderPtr(MapFilePtr));
  psh := PImageSectionHeader(GetPeSectionHeader32Ptr(MapFilePtr));
  nSections := GetPeNumberOfSections(MapFilePtr);
  i := 0;

  // deve ser 0 a (NumberOfRvaAndSizes-1)
  if ImageDirectory >= poh^.NumberOfDataDirectoryEntries then
    Exit(nil);

  // localize o endereço virtual relativo do diretório de imagem específico
  VAImageDir := poh^.DataDirectory[ImageDirectory].VirtualAddress;

  // localize a seção que contém o diretório de imagens
  while (i < nSections) do
  begin
    Inc(i);

    if (psh^.VirtualAddress <= VAImageDir) and
       ((psh^.VirtualAddress + psh^.SizeOfRawData) > VAImageDir) then
        break;

    Inc(psh);
  end;

  if (i > nSections) then
    Exit(nil);

  // devolve o deslocamento do directório de importação de imagens
  Result := Pointer((DWORD(MapFilePtr) +
                     VAImageDir -
                     psh^.VirtualAddress) +
                     psh^.PointerToRawData);
end;

function GetPeDosHeader(MapFilePtr: Pointer; HeaderPtr: PImageDosHeader): Boolean;
begin
  // DOS header representa a primeira estrutura de bytes no arquivo
  if WORD(MapFilePtr^) = IMAGE_DOS_SIGNATURE then
  begin
    Move(MapFilePtr^, HeaderPtr^, SizeOf(TImageDosHeader));
    Result := True;
  end
  else
    Result := False;
end;


end.
