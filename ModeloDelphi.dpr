program ModeloDelphi;

uses
  windows;

var
 Ponteiro: Cardinal;
begin

  Ponteiro := Cardinal(@MessageBox);

  asm
    push 0
    push 0
    push 0
    push 0
    call Ponteiro
  end;

end.
