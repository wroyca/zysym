module;

#include <LIEF/LIEF.hpp>

#include <dia2.h>
#include <diacreate.h>
#include <atlcomcli.h>
#include <comdef.h>
#include <comutil.h>

#include <Zydis/Zydis.h>
#include <Zycore/Format.h>

#include <string>
#include <iostream>
#include <format>
#include <fstream>

import dia;
export module disassemble;
export

namespace ZySym {
namespace {

ZydisFormatterFunc ZydisDecodeAbsolute;
ZydisFormatterFunc ZydisDecodeImmediate;
ZydisFormatterFunc ZydisDecodeRegister;

enum class Operand {
  Absolute,
  Immediate,
  Register,
};

auto zydis_decode_register(const ZydisFormatter *formatter, ZydisFormatterBuffer *buffer, ZydisFormatterContext *context) -> ZyanStatus
{
  return ZydisDecodeRegister(formatter, buffer, context);
}

auto zydis_decode_immediate(const ZydisFormatter *formatter, ZydisFormatterBuffer *buffer, ZydisFormatterContext *context) -> ZyanStatus
{
  return ZydisDecodeImmediate(formatter, buffer, context);
}

auto zydis_decode_absolute(const ZydisFormatter *formatter, ZydisFormatterBuffer *buffer, ZydisFormatterContext *context) -> ZyanStatus
{
  ZyanU64 address;
  ZYAN_CHECK(ZydisCalcAbsoluteAddress(context->instruction, context->operand, context->runtime_address, &address));
  CComPtr<IDiaSymbol> symbol;

  // name is allocated by get_name, so we copy the underlying C
  // string and free the memory.
  auto Helper = [&](auto offset) {
    wchar_t* name = L""; symbol->get_name(&name); std::wstring copy = name; SysFreeString(name);
    ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, ZYDIS_TOKEN_SYMBOL));
    ZyanString* string;
    ZYAN_CHECK(ZydisFormatterBufferGetString(buffer, &string));
    return ZyanStringAppendFormat(string, offset == 0 ? "%ls" : "%ls+0x%s", copy.c_str(), std::format("{:x}", offset).c_str());
  };

  // For SymTagFunction, we don't need to do anything special. We can just use the address.
  if (context->instruction->mnemonic == ZYDIS_MNEMONIC_CALL) {
    if (SUCCEEDED(dia_session->findSymbolByRVA(address, SymTagFunction, &symbol)) && symbol != nullptr) {
      return Helper(0);
    }
  }

  // Substract the imagebase to get the RVA. This is the address we want to look up.
  if (address -= 0x00400000; address < 0xFFFFFFFF) {
    if (SUCCEEDED(dia_session->findSymbolByRVA(address, SymTagData, &symbol)) && symbol != nullptr) {
      // Calculate the struct offset discarded by dia. We do this by
      // subtracting the difference between the address and the
      // symbol's address. This is only possible because dia always
      // returns the symbol's base address.
      auto rva = 0ul; symbol->get_relativeVirtualAddress(&rva); auto offset = address - rva;
      return Helper(offset);
    }
  }

  return ZydisDecodeAbsolute(formatter, buffer, context);
}

} // namespace

auto zydis_decode(std::wstring pdb, const wchar_t *sym_name)
{
  auto [address, length] = get_symbol_by_name(sym_name, SymTagFunction);

  auto binary  = pdb.substr(0, pdb.find_last_of('.')) + L".exe";
  auto output  = pdb.substr(0, pdb.find_last_of('.')) + L".txt";
  auto parser  = LIEF::PE::Parser::parse(std::string(binary.begin(), binary.end()).c_str());
  auto content = parser->get_content_from_virtual_address(address, length, LIEF::Binary::VA_TYPES::RVA);

  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

  ZydisFormatter formatter;
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

  ZydisDecodeAbsolute = (ZydisFormatterFunc)&zydis_decode_absolute;
  ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS, (const void**)&ZydisDecodeAbsolute);
//ZydisDecodeRegister = (ZydisFormatterFunc)&zydis_decode_register;
//ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_REGISTER, (const void**)&ZydisDecodeRegister);
//ZydisDecodeImmediate = &zydis_decode_immediate;
//ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_IMM, (const void**)&ZydisDecodeImmediate);

  ZyanU8* data = &content[0];
  ZyanU64 runtime_address = address;
  ZyanUSize offset = 0;
  ZydisDecodedInstruction instruction;
  ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
  std::ofstream file_stream(output, std::ios_base::app);

  while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, length - offset, &instruction, operands, ZYDIS_MAX_OPERAND_COUNT_VISIBLE, ZYDIS_DFLAG_VISIBLE_OPERANDS_ONLY))) {
    char buffer[256];
    ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible, buffer, sizeof(buffer), runtime_address);
    offset += instruction.length;
    runtime_address += instruction.length;
    file_stream << buffer << "\n";
  }
}

} // namespace ZySym
