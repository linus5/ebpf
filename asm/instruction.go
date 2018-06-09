package asm

import (
	"fmt"
)

// Instruction is a single eBPF instruction.
type Instruction struct {
	OpCode      OpCode
	DstRegister Register
	SrcRegister Register
	Offset      int16
	Constant    int64
	Reference   string
	Symbol      string
}

// Ref creates a reference to a symbol.
func (ins Instruction) Ref(symbol string) Instruction {
	ins.Reference = symbol
	return ins
}

// Sym creates a symbol.
func (ins Instruction) Sym(name string) Instruction {
	ins.Symbol = name
	return ins
}

// EncodedLength returns the encoded length in number of instructions.
func (ins Instruction) EncodedLength() int {
	if ins.OpCode.Size() == DWSize {
		return 2
	}
	return 1
}

var classMap = map[Class]string{
	LdClass:    "Ld",
	LdXClass:   "LdX",
	StClass:    "St",
	StXClass:   "StX",
	ALUClass:   "ALU32",
	JmpClass:   "Jmp",
	RetClass:   "Rt",
	ALU64Class: "ALU64",
}

func (ins Instruction) String() string {
	var opStr string
	op := ins.OpCode
	var class, dst, src, off, imm string
	var alu32 string
	switch cls := op.Class(); cls {
	case RetClass, LdClass, LdXClass, StClass, StXClass:
		class = classMap[cls]
		mode := ""
		xAdd := false
		dst = fmt.Sprintf(" dst: %s", ins.DstRegister)
		switch op.Mode() {
		case ImmMode:
			mode = "Imm"
			imm = fmt.Sprintf(" imm: %d", ins.Constant)
		case AbsMode:
			mode = "Abs"
			dst = ""
			imm = fmt.Sprintf(" imm: %d", ins.Constant)
			off = ""
		case IndMode:
			mode = "Ind"
			src = fmt.Sprintf(" src: %s", ins.SrcRegister)
			imm = fmt.Sprintf(" imm: %d", ins.Constant)
			off = ""
		case MemMode:
			src = fmt.Sprintf(" src: %s", ins.SrcRegister)
			off = fmt.Sprintf(" off: %d", ins.Offset)
			imm = fmt.Sprintf(" imm: %d", ins.Constant)
		case LenMode:
			mode = "Len"
		case MshMode:
			mode = "Msh"
		case XAddMode:
			mode = "XAdd"
			src = fmt.Sprintf(" src: %s", ins.SrcRegister)
			xAdd = true
		}
		size := ""
		switch op.Size() {
		case DWSize:
			size = "DW"
		case WSize:
			size = "W"
		case HSize:
			size = "H"
		case BSize:
			size = "B"
		}
		if xAdd {
			opStr = fmt.Sprintf("%s%s", mode, class)
		}
		opStr = fmt.Sprintf("%s%s%s", class, mode, size)
	case ALU64Class, ALUClass:
		if cls == ALUClass {
			alu32 = "32"
		}
		dst = fmt.Sprintf(" dst: %s", ins.DstRegister)
		opSuffix := ""
		if op.Source() == ImmSource {
			imm = fmt.Sprintf(" imm: %d", ins.Constant)
			opSuffix = "Imm"
		} else {
			src = fmt.Sprintf(" src: %s", ins.SrcRegister)
			opSuffix = "Src"
		}
		opPrefix := ""
		switch op.ALUOp() {
		case AddOp:
			opPrefix = "Add"
		case SubOp:
			opPrefix = "Sub"
		case MulOp:
			opPrefix = "Mul"
		case DivOp:
			opPrefix = "Div"
		case OrOp:
			opPrefix = "Or"
		case AndOp:
			opPrefix = "And"
		case LShOp:
			opPrefix = "LSh"
		case RShOp:
			opPrefix = "RSh"
		case NegOp:
			opPrefix = "Neg"
		case ModOp:
			opPrefix = "Mod"
		case XOrOp:
			opPrefix = "XOr"
		case MovOp:
			opPrefix = "Mov"
		case ArShOp:
			opPrefix = "ArSh"
		case EndOp:
			alu32 = ""
			src = ""
			imm = fmt.Sprintf(" imm: %d", ins.Constant)
			opPrefix = "LittleEndian"
			if op.Source() == BigEndian {
				opPrefix = "BigEndian"
			}
			opPrefix = ""
		}
		opStr = fmt.Sprintf("%s%s%s", opPrefix, alu32, opSuffix)
	case JmpClass:
		dst = fmt.Sprintf(" dst: %s", ins.DstRegister)
		off = fmt.Sprintf(" off: %d", ins.Offset)
		opSuffix := ""
		if op.Source() == ImmSource {
			imm = fmt.Sprintf(" imm: %d", ins.Constant)
			opSuffix = "Imm"
		} else {
			src = fmt.Sprintf(" src: %s", ins.SrcRegister)
			opSuffix = "Src"
		}
		opPrefix := ""
		switch op.BranchOp() {
		case JaOp:
			opPrefix = "Ja"
		case JEqOp:
			opPrefix = "JEq"
		case JGTOp:
			opPrefix = "JGT"
		case JGEOp:
			opPrefix = "JGE"
		case JSETOp:
			opPrefix = "JSET"
		case JNEOp:
			opPrefix = "JNE"
		case JSGTOp:
			opPrefix = "JSGT"
		case JSGEOp:
			opPrefix = "JSGE"
		case CallOp:
			imm = ""
			src = ""
			off = ""
			dst = ""
			opPrefix = "Call"
			if ins.SrcRegister == R1 {
				// bpf-to-bpf call
				opSuffix = fmt.Sprintf(" %v", ins.Constant)
			} else {
				opSuffix = fmt.Sprintf(" %v", Func(ins.Constant))
			}

		case ExitOp:
			imm = ""
			src = ""
			off = ""
			dst = ""
			opSuffix = ""
			opPrefix = "Exit"
		}
		opStr = fmt.Sprintf("%s%s", opPrefix, opSuffix)
	}
	return fmt.Sprintf("%s%s%s%s%s", opStr, dst, src, off, imm)
}
