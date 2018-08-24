unit Se7e.AsmEncoder;

interface

const
  ASM_ENCODER_MAX_BUFFER_SIZE = 256;
  ASM_ENCODER_MAX_SIZE = 16;

type

  TCallBackAsmEncoderUnknown = function(Text: PAnsiChar; Value: PUInt64): Boolean;

  TAsmEncoderStatus = (ASM_ENCODER_ERROR = 0, ASM_ENCODER_OK = 1);

  TAsmEncoderPtr = ^TAsmEncoder;
  TAsmEncoder = record
    x64: boolean; // use 64-bit instructions
    cip: UInt64; //instruction pointer (for relative addressing)
    dest_size: UInt32; //destination size (returned by XEDParse)
    CallBackUnknown: TCallBackAsmEncoderUnknown; //unknown operand callback
    dest: array[0..ASM_ENCODER_MAX_SIZE-1] of Byte; //destination buffer
    instr: array[0..ASM_ENCODER_MAX_BUFFER_SIZE-1] of AnsiChar; //instruction text
    error: array[0..ASM_ENCODER_MAX_BUFFER_SIZE-1] of AnsiChar; //error text (in case of an error)
  end;

  function AsmEncoderInstruction(const Instruction: TAsmEncoderPtr): TAsmEncoderStatus;

implementation

function AsmEncoderInstruction(const Instruction: TAsmEncoderPtr): TAsmEncoderStatus;
begin
  Result := ASM_ENCODER_ERROR;
end;

end.
