unit Se7e.XED;

interface

const
  XED_ENCODE_ORDER_MAX_OPERANDS = 5;

type

  TXEDUnsignedInt8 = UInt8;
  TXEDUnsignedInt16 = UInt16;
  TXEDUnsignedInt32 = UInt32;
  TXEDUnsignedInt64 = UInt64;
  TXEDUnsignedInt8Ptr = ^TXEDUnsignedInt8;
  TXEDUnsignedInt16Ptr = ^TXEDUnsignedInt16;
  TXEDUnsignedInt32Ptr = ^TXEDUnsignedInt32;
  TXEDUnsignedInt64Ptr = ^TXEDUnsignedInt64;

  TXEDErrorEnum = (
  XED_ERROR_NONE, ///< There was no error
  XED_ERROR_BUFFER_TOO_SHORT, ///< There were not enough bytes in the given buffer
  XED_ERROR_GENERAL_ERROR, ///< XED could not decode the given instruction
  XED_ERROR_INVALID_FOR_CHIP, ///< The instruciton is not valid for the specified chip
  XED_ERROR_BAD_REGISTER, ///< XED could not decode the given instruction because an invalid register encoding was used.
  XED_ERROR_BAD_LOCK_PREFIX, ///< A lock prefix was found where none is allowed.
  XED_ERROR_BAD_REP_PREFIX, ///< An F2 or F3 prefix was found where none is allowed.
  XED_ERROR_BAD_LEGACY_PREFIX, ///< A 66, F2 or F3 prefix was found where none is allowed.
  XED_ERROR_BAD_REX_PREFIX, ///< A REX prefix was found where none is allowed.
  XED_ERROR_BAD_EVEX_UBIT, ///< An illegal value for the EVEX.U bit was present in the instruction.
  XED_ERROR_BAD_MAP, ///< An illegal value for the MAP field was detected in the instruction.
  XED_ERROR_BAD_EVEX_V_PRIME, ///< EVEX.V'=0 was detected in a non-64b mode instruction.
  XED_ERROR_BAD_EVEX_Z_NO_MASKING, ///< EVEX.Z!=0 when EVEX.aaa==0
  XED_ERROR_NO_OUTPUT_POINTER, ///< The output pointer for xed_agen was zero
  XED_ERROR_NO_AGEN_CALL_BACK_REGISTERED, ///< One or both of the callbacks for xed_agen were missing.
  XED_ERROR_BAD_MEMOP_INDEX, ///< Memop indices must be 0 or 1.
  XED_ERROR_CALLBACK_PROBLEM, ///< The register or segment callback for xed_agen experienced a problem
  XED_ERROR_GATHER_REGS, ///< The index, dest and mask regs for AVX2 gathers must be different.
  XED_ERROR_INSTR_TOO_LONG, ///< Full decode of instruction would exeed 15B.
  XED_ERROR_INVALID_MODE, ///< The instruction was not valid for the specified mode
  XED_ERROR_BAD_EVEX_LL, ///< EVEX.LL must not ==3 unless using embedded rounding
  XED_ERROR_LAST
);

  TXEDMachineMode =
(
    XED_MACHINE_MODE_INVALID,
    XED_MACHINE_MODE_LONG_64, ///< 64b operating mode
    XED_MACHINE_MODE_LONG_COMPAT_32, ///< 32b protected mode
    XED_MACHINE_MODE_LONG_COMPAT_16, ///< 16b protected mode
    XED_MACHINE_MODE_LEGACY_32, ///< 32b protected mode
    XED_MACHINE_MODE_LEGACY_16, ///< 16b protected mode
    XED_MACHINE_MODE_REAL_16, ///< 16b real mode
    XED_MACHINE_MODE_LAST
);


  TXEDAddressWidth =
(
    XED_ADDRESS_WIDTH_INVALID = 0,
    XED_ADDRESS_WIDTH_16b = 2, ///< 16b addressing
    XED_ADDRESS_WIDTH_32b = 4, ///< 32b addressing
    XED_ADDRESS_WIDTH_64b = 8, ///< 64b addressing
    XED_ADDRESS_WIDTH_LAST
);


/// Encapsulates machine modes for decoder/encoder requests.
/// It specifies the machine operating mode as a
/// #xed_machine_mode_enum_t
/// for decoding and encoding. The machine mode corresponds to the default
/// data operand width for that mode. For all modes other than the 64b long
/// mode (XED_MACHINE_MODE_LONG_64), a default addressing width, and a
/// stack addressing width must be supplied of type
/// #xed_address_width_enum_t .  @ingroup INIT
    TXEDState = record
    /// real architected machine modes
      mmode: TXEDMachineMode;
    /// for 16b/32b modes
      stack_addr_width: TXEDAddressWidth;
    end;


/// @ingroup DEC
/// constant information about a decoded instruction form, including
/// the pointer to the constant operand properties #xed_operand_t for this
/// instruction form.
// struct xed_inst_s, xed_inst_t {

  TXEDInstructionPtr = ^TXEDInstruction;
  TXEDInstruction = packed record
    // rflags info -- index in to the 2 tables of flags information.
    // If _flag_complex is true, then the data are in the
    // xed_flags_complex_table[]. Otherwise, the data are in the
    // xed_flags_simple_table[].

    //xed_instruction_fixed_bit_confirmer_fn_t _confirmer;

    // number of operands in the operands array
    _noperands: TXEDUnsignedInt8 ;
    _cpl: TXEDUnsignedInt8 ;  // the nominal CPL for the instruction.
    _flag_complex: TXEDUnsignedInt8 ; //* 1/0 valued, bool type */
    _exceptions: TXEDUnsignedInt8 ; //xed_exception_enum_t

    _flag_info_index: TXEDUnsignedInt16 ;

    _iform_enum: TXEDUnsignedInt16  ; //xed_iform_enum_t
    // index into the xed_operand[] array of xed_operand_t structures
    _operand_base: TXEDUnsignedInt16 ;
    // index to table of xed_attributes_t structures
    _attributes: TXEDUnsignedInt16 ;

  end;


  TXEDOperandStoragePtr = ^TXEDOperandStorage;
  TXEDOperandStorage = packed record
    agen: TXEDUnsignedInt8;
    amd3dnow: TXEDUnsignedInt8;
    asz: TXEDUnsignedInt8;
    bcrc: TXEDUnsignedInt8;
    cet: TXEDUnsignedInt8;
    cldemote: TXEDUnsignedInt8;
    df32: TXEDUnsignedInt8;
    df64: TXEDUnsignedInt8;
    dummy: TXEDUnsignedInt8;
    encoder_preferred: TXEDUnsignedInt8;
    has_sib: TXEDUnsignedInt8;
    ild_f2: TXEDUnsignedInt8 ;
    ild_f3: TXEDUnsignedInt8 ;
    imm0: TXEDUnsignedInt8 ;
    imm0signed: TXEDUnsignedInt8 ;
    imm1: TXEDUnsignedInt8 ;
    lock: TXEDUnsignedInt8 ;
    lzcnt: TXEDUnsignedInt8 ;
    mem0: TXEDUnsignedInt8 ;
    mem1: TXEDUnsignedInt8 ;
    modep5: TXEDUnsignedInt8 ;
    modep55c: TXEDUnsignedInt8 ;
    mode_first_prefix: TXEDUnsignedInt8 ;
    mpxmode: TXEDUnsignedInt8 ;
    needrex: TXEDUnsignedInt8 ;
    norex: TXEDUnsignedInt8 ;
    no_scale_disp8: TXEDUnsignedInt8;
    osz: TXEDUnsignedInt8;
    out_of_bytes: TXEDUnsignedInt8;
    p4: TXEDUnsignedInt8;
    prefix66: TXEDUnsignedInt8;
    ptr: TXEDUnsignedInt8;
    realmode: TXEDUnsignedInt8;
    relbr: TXEDUnsignedInt8;
    rex: TXEDUnsignedInt8;
    rexb: TXEDUnsignedInt8;
    rexr: TXEDUnsignedInt8;
    rexrr: TXEDUnsignedInt8;
    rexw: TXEDUnsignedInt8;
    rexx: TXEDUnsignedInt8;
    sae: TXEDUnsignedInt8;
    sib: TXEDUnsignedInt8;
    skip_osz: TXEDUnsignedInt8;
    tzcnt: TXEDUnsignedInt8;
    ubit: TXEDUnsignedInt8;
    using_default_segment0: TXEDUnsignedInt8;
    using_default_segment1: TXEDUnsignedInt8;
    vexdest3: TXEDUnsignedInt8;
    vexdest4: TXEDUnsignedInt8;
    vex_c4: TXEDUnsignedInt8;
    wbnoinvd: TXEDUnsignedInt8;
    zeroing: TXEDUnsignedInt8;
    default_seg: TXEDUnsignedInt8;
    easz: TXEDUnsignedInt8;
    eosz: TXEDUnsignedInt8;
    first_f2f3: TXEDUnsignedInt8;
    has_modrm: TXEDUnsignedInt8;
    last_f2f3: TXEDUnsignedInt8;
    llrc: TXEDUnsignedInt8;
    mod_: TXEDUnsignedInt8;
    mode: TXEDUnsignedInt8;
    rep: TXEDUnsignedInt8;
    sibscale: TXEDUnsignedInt8;
    smode: TXEDUnsignedInt8;
    vex_prefix: TXEDUnsignedInt8;
    vl: TXEDUnsignedInt8;
    hint: TXEDUnsignedInt8;
    mask: TXEDUnsignedInt8;
    reg: TXEDUnsignedInt8;
    rm: TXEDUnsignedInt8;
    roundc: TXEDUnsignedInt8;
    seg_ovd: TXEDUnsignedInt8;
    sibbase: TXEDUnsignedInt8;
    sibindex: TXEDUnsignedInt8;
    srm: TXEDUnsignedInt8;
    vexdest210: TXEDUnsignedInt8;
    vexvalid: TXEDUnsignedInt8;
    error: TXEDUnsignedInt8;
    esrc: TXEDUnsignedInt8;
    map: TXEDUnsignedInt8;
    nelem: TXEDUnsignedInt8;
    scale: TXEDUnsignedInt8;
    bcast: TXEDUnsignedInt8;
    chip: TXEDUnsignedInt8;
    need_memdisp: TXEDUnsignedInt8;
    brdisp_width: TXEDUnsignedInt8;
    disp_width: TXEDUnsignedInt8;
    ild_seg: TXEDUnsignedInt8;
    imm1_bytes: TXEDUnsignedInt8;
    imm_width: TXEDUnsignedInt8;
    max_bytes: TXEDUnsignedInt8;
    modrm_byte: TXEDUnsignedInt8;
    nominal_opcode: TXEDUnsignedInt8;
    nprefixes: TXEDUnsignedInt8;
    nrexes: TXEDUnsignedInt8;
    nseg_prefixes: TXEDUnsignedInt8;
    pos_disp: TXEDUnsignedInt8;
    pos_imm: TXEDUnsignedInt8;
    pos_imm1: TXEDUnsignedInt8;
    pos_modrm: TXEDUnsignedInt8;
    pos_nominal_opcode: TXEDUnsignedInt8;
    pos_sib: TXEDUnsignedInt8;
    uimm1: TXEDUnsignedInt8;
    base0: TXEDUnsignedInt16;
    base1: TXEDUnsignedInt16;
    element_size: TXEDUnsignedInt16;
    index: TXEDUnsignedInt16;
    outreg: TXEDUnsignedInt16;
    reg0: TXEDUnsignedInt16;
    reg1: TXEDUnsignedInt16;
    reg2: TXEDUnsignedInt16;
    reg3: TXEDUnsignedInt16;
    reg4: TXEDUnsignedInt16;
    reg5: TXEDUnsignedInt16;
    reg6: TXEDUnsignedInt16;
    reg7: TXEDUnsignedInt16;
    reg8: TXEDUnsignedInt16;
    seg0: TXEDUnsignedInt16;
    seg1: TXEDUnsignedInt16;
    iclass: TXEDUnsignedInt16;
    mem_width: TXEDUnsignedInt16;
    disp: TXEDUnsignedInt64;
    uimm0: TXEDUnsignedInt64;
  end;

  TXEDEncoderIFormsPtr = ^TXEDEncoderIForms;
  TXEDEncoderIForms = packed record
    x_SIBBASE_ENCODE: TXEDUnsignedInt32;
    x_SIBBASE_ENCODE_SIB1: TXEDUnsignedInt32;
    x_SIBINDEX_ENCODE: TXEDUnsignedInt32;
    x_MODRM_MOD_ENCODE: TXEDUnsignedInt32;
    x_MODRM_RM_ENCODE: TXEDUnsignedInt32;
    x_MODRM_RM_ENCODE_EA16_SIB0: TXEDUnsignedInt32;
    x_MODRM_RM_ENCODE_EA64_SIB0: TXEDUnsignedInt32;
    x_MODRM_RM_ENCODE_EA32_SIB0: TXEDUnsignedInt32;
    x_SIB_NT: TXEDUnsignedInt32;
    x_DISP_NT: TXEDUnsignedInt32;
    x_REMOVE_SEGMENT: TXEDUnsignedInt32;
    x_REX_PREFIX_ENC: TXEDUnsignedInt32;
    x_PREFIX_ENC: TXEDUnsignedInt32;
    x_VEXED_REX: TXEDUnsignedInt32;
    x_XOP_TYPE_ENC: TXEDUnsignedInt32;
    x_XOP_MAP_ENC: TXEDUnsignedInt32;
    x_XOP_REXXB_ENC: TXEDUnsignedInt32;
    x_VEX_TYPE_ENC: TXEDUnsignedInt32;
    x_VEX_REXR_ENC: TXEDUnsignedInt32;
    x_VEX_REXXB_ENC: TXEDUnsignedInt32;
    x_VEX_MAP_ENC: TXEDUnsignedInt32;
    x_VEX_REG_ENC: TXEDUnsignedInt32;
    x_VEX_ESCVL_ENC: TXEDUnsignedInt32;
    x_SE_IMM8: TXEDUnsignedInt32;
    x_VSIB_ENC_BASE: TXEDUnsignedInt32;
    x_VSIB_ENC: TXEDUnsignedInt32;
    x_EVEX_62_REXR_ENC: TXEDUnsignedInt32;
    x_EVEX_REXX_ENC: TXEDUnsignedInt32;
    x_EVEX_REXB_ENC: TXEDUnsignedInt32;
    x_EVEX_REXRR_ENC: TXEDUnsignedInt32;
    x_EVEX_MAP_ENC: TXEDUnsignedInt32;
    x_EVEX_REXW_VVVV_ENC: TXEDUnsignedInt32;
    x_EVEX_UPP_ENC: TXEDUnsignedInt32;
    x_AVX512_EVEX_BYTE3_ENC: TXEDUnsignedInt32;
    x_UIMMv: TXEDUnsignedInt32;
    x_SIMMz: TXEDUnsignedInt32;
    x_SIMM8: TXEDUnsignedInt32;
    x_UIMM8: TXEDUnsignedInt32;
    x_UIMM8_1: TXEDUnsignedInt32;
    x_UIMM16: TXEDUnsignedInt32;
    x_UIMM32: TXEDUnsignedInt32;
    x_BRDISP8: TXEDUnsignedInt32;
    x_BRDISP32: TXEDUnsignedInt32;
    x_BRDISPz: TXEDUnsignedInt32;
    x_MEMDISPv: TXEDUnsignedInt32;
    x_MEMDISP32: TXEDUnsignedInt32;
    x_MEMDISP16: TXEDUnsignedInt32;
    x_MEMDISP8: TXEDUnsignedInt32;
    x_MEMDISP: TXEDUnsignedInt32;
  end;


  TXEDEncoderVars = packed record
    /// _iforms is a dynamically generated structure containing the values of
    /// various encoding decisions
    _iforms: TXEDEncoderIForms;

    // the index of the iform in the xed_encode_iform_db table
    _iform_index: TXEDUnsignedInt16;

    /// Encode output array size, specified by caller of xed_encode()
    _ilen: TXEDUnsignedInt32;

    /// Used portion of the encode output array
    _olen: TXEDUnsignedInt32;

    _bit_offset: TXEDUnsignedInt32;
end;


    /// @ingroup DEC
    /// The main container for instructions. After decode, it holds an array of
    /// operands with derived information from decode and also valid
    /// #xed_inst_t pointer which describes the operand templates and the
    /// operand order.  See @ref DEC for API documentation.
  TXEDDecodedInstructionPtr = ^TXEDDecodedInstruction;
  TXEDDecodedInstruction = packed record
    /// The _operands are storage for information discovered during
    /// decoding. They are also used by encode.  The accessors for these
    /// operands all have the form xed3_operand_{get,set}_*(). They should
    /// be considered internal and subject to change over time. It is
    /// preferred that you use xed_decoded_inst_*() or the
    /// xed_operand_values_*() functions when available.
    _operands: TXEDOperandStorage;

    /// Used for encode operand ordering. Not set by decode.
    _operand_order: array[0..XED_ENCODE_ORDER_MAX_OPERANDS-1] of TXEDUnsignedInt8;
    /// Length of the _operand_order[] array.
    _n_operand_order: TXEDUnsignedInt8 ;
    _decoded_length: TXEDUnsignedInt8 ;

    /// when we decode an instruction, we set the _inst and get the
    /// properites of that instruction here. This also points to the
    /// operands template array.
    _inst: TXEDInstructionPtr;

    // decoder does not change it, encoder does
    _byte_array: packed record
                   case Integer of
                   0: (_enc: TXEDUnsignedInt8Ptr);
                   1: (_dec: TXEDUnsignedInt8Ptr);
                 end;

    // The ev field is stack allocated by xed_encode(). It is per-encode
    // transitory data.
    u: packed record
          //* user_data is available as a user data storage field after
          // * decoding. It does not live across re-encodes or re-decodes. */
          case Integer of
          0: (user_data: TXEDUnsignedInt64);
          1: (ev: TXEDEncoderIFormsPtr);
          end;
  end;

 TXEDEncoderRequestPtr = ^TXEDEncoderRequest;
 TXEDEncoderRequest = TXEDDecodedInstruction;

procedure xed_tables_init; cdecl; external 'xed.dll';

/// @name Encoding
//@{
///   This is the main interface to the encoder. The array should be
///   at most 15 bytes long. The ilen parameter should indicate
///   this length. If the array is too short, the encoder may fail to
///   encode the request.  Failure is indicated by a return value of
///   type #xed_error_enum_t that is not equal to
///   #XED_ERROR_NONE. Otherwise, #XED_ERROR_NONE is returned and the
///   length of the encoded instruction is returned in olen.
///
/// @param r encoder request description (#xed_encoder_request_t), includes mode info
/// @param array the encoded instruction bytes are stored here
/// @param ilen the input length of array.
/// @param olen the actual  length of array used for encoding
/// @return success/failure as a #xed_error_enum_t
/// @ingroup ENC
function xed_encode(r: TXEDEncoderRequestPtr;
                    arr: TXEDUnsignedInt8Ptr;
                    ilen: UInt32;
                    olen: TXEDUnsignedInt32Ptr): TXEDErrorEnum; cdecl; external 'xed.dll';


implementation

initialization
  xed_tables_init();

end.
