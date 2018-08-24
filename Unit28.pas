unit Unit28;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Se7e.PEFile.API, Se7e.PeFile;

type
  TForm28 = class(TForm)
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form28: TForm28;

implementation

{$R *.dfm}

procedure TForm28.FormCreate(Sender: TObject);
var
  PeFile: TPeFile;
begin

//  PeFile := OpenPeFile('A:\x64dbg\release\x64\x64dbg.exe');
  PeFile := OpenPeFile('A:\x64dbg\release\x32\x32dbg.exe');

''.PadLeft(7);

//  ShowMessage('O cabeçalho do DOS tem '+ IntToStr(SizeOfImageDosHeader) + ' bytes ou ' + IntToStr(SizeOfImageDosHeader*8) + ' bits'#13#10+
//              'O cabeçalho PE tem '+ IntToStr(SizeOfImageNtHeaders32) + ' bytes ou ' + IntToStr(SizeOfImageNtHeaders32*8) + ' bits'#13#10+
//              'FileHeader tem '+ IntToStr(SizeOfImageFileHeader) + ' bytes ou ' + IntToStr(SizeOfImageFileHeader*8) + ' bits'#13#10+
//              'O Diretório de Dados tem '+ IntToStr(SizeOfImageDataDirectory) + ' bytes ou ' + IntToStr(SizeOfImageDataDirectory*8) + ' bits'#13#10+
//              'A Tabela de Seção tem '+ IntToStr(SizeOfImageSectionHeader) + ' bytes ou ' + IntToStr(SizeOfImageSectionHeader*8) + ' bits'#13#10+
//              'A Seção de Exportação tem '+ IntToStr(SizeOfImageExportDirectory) + ' bytes ou ' + IntToStr(SizeOfImageExportDirectory*8) + ' bits'#13#10+
//              'O diretório de importação tem '+ IntToStr(SizeOfImageImportDescriptor) + ' bytes ou ' + IntToStr(SizeOfImageImportDescriptor*8) + ' bits'#13#10+
//              '');

end;

end.
