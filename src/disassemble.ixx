module;

#include <Zydis/Zydis.h>
#include <LIEF/LIEF.hpp>

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
  return ZydisDecodeAbsolute(formatter, buffer, context);
}

} // namespace

auto zydis_decode(std::wstring pdb, const wchar_t *sym_name)
{
  auto [address, length] = get_symbol_from_name(sym_name, SymTagFunction);

  auto binary = pdb.substr(0, pdb.find_last_of('.')) + L".exe";
  auto output = pdb.substr(0, pdb.find_last_of('.')) + L".txt";
  auto parser = LIEF::PE::Parser::parse(std::string(binary.begin(), binary.end()).c_str());
  auto content = parser->get_content_from_virtual_address(address, length, LIEF::Binary::VA_TYPES::RVA);

  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);

  ZydisFormatter formatter;
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

  ZydisDecodeAbsolute = &zydis_decode_absolute;
  ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS, (const void**)&ZydisDecodeAbsolute);
  ZydisDecodeImmediate = &zydis_decode_immediate;
  ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS, (const void**)&ZydisDecodeImmediate);
  ZydisDecodeRegister = &zydis_decode_register;
  ZydisFormatterSetHook(&formatter, ZYDIS_FORMATTER_FUNC_PRINT_ADDRESS_ABS, (const void**)&ZydisDecodeRegister);

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
