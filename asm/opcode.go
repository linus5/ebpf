package asm

//go:generate stringer -output opcode_string.go -type=Class,Size,Mode,Source,ALUOp,BranchOp

type encoding int

const (
	unknownEncoding encoding = iota
	loadOrStore
	branchOrALU
)

// Class of operations
//
//    msb      lsb
//    +---+--+---+
//    |mde|sz|CLS|
//    +---+--+---+
type Class uint8

const classMask OpCode = 0x07

const (
	// LdClass load memory
	LdClass Class = 0x00
	// LdXClass load memory from constant
	LdXClass Class = 0x01
	// StClass load registry from memory
	StClass Class = 0x02
	// StXClass load registry from constan
	StXClass Class = 0x03
	// ALUClass arithmetic operators
	ALUClass Class = 0x04
	// JmpClass jump operators
	JmpClass Class = 0x05
	// RetClass return operator
	RetClass Class = 0x06
	// MiscClass exit, et al operators
	MiscClass Class = 0x07
	// ALU64Class arithmetic in 64 bit mode; eBPF only
	ALU64Class Class = 0x07
)

func (cls Class) encoding() encoding {
	switch cls {
	case LdClass, LdXClass, StClass, StXClass:
		return loadOrStore
	case ALU64Class, ALUClass, JmpClass, RetClass:
		return branchOrALU
	default:
		return unknownEncoding
	}
}

// Size load and store operations
//
//    msb      lsb
//    +---+--+---+
//    |mde|SZ|cls|
//    +---+--+---+
type Size uint8

const sizeMask OpCode = 0x18

const (
	// InvalidSize is returned by getters when invoked
	// on non load / store OpCodes
	InvalidSize Size = 0xff
	// DWSize - double word; 64 bits; eBPF only
	DWSize Size = 0x18
	// WSize - word; 32 bits
	WSize Size = 0x00
	// HSize - half-word; 16 bits
	HSize Size = 0x08
	// BSize - byte; 8 bits
	BSize Size = 0x10
)

// Mode for load and store operations
//
//    msb      lsb
//    +---+--+---+
//    |MDE|sz|cls|
//    +---+--+---+
type Mode uint8

const modeMask OpCode = 0xe0

const (
	// InvalidMode is returned by getters when invoked
	// on non load / store OpCodes
	InvalidMode Mode = 0xff
	// ImmMode - immediate value
	ImmMode Mode = 0x00
	// AbsMode - immediate value + offset
	AbsMode Mode = 0x20
	// IndMode - indirect (imm+src)
	IndMode Mode = 0x40
	// MemMode - load from memory
	MemMode Mode = 0x60
	// LenMode - ??
	LenMode Mode = 0x80
	// MshMode - ??
	MshMode Mode = 0xa0
	// XAddMode - add atomically across processors; eBPF only.
	XAddMode Mode = 0xc0
)

// Source of ALU / ALU64 / Branch operations
//
//    msb      lsb
//    +----+-+---+
//    |op  |S|cls|
//    +----+-+---+
type Source uint8

const sourceMask OpCode = 0x08

// Source bitmask
const (
	// InvalidSource is returned by getters when invoked
	// on non ALU / branch OpCodes.
	InvalidSource Source = 0xff
	// ImmSource src is from constant
	ImmSource Source = 0x00
	// RegSource src is from register
	RegSource Source = 0x08
	// Convert from / to little endian for EndOp
	LittleEndian Source = 0x00
	// Convert from / to big endian for EndOp
	BigEndian Source = 0x00
)

// ALUOp are ALU / ALU64 operations
//
//    msb      lsb
//    +----+-+---+
//    |OP  |s|cls|
//    +----+-+---+
type ALUOp uint8

const aluMask OpCode = 0xf0

const (
	// InvalidALUOp is returned by getters when invoked
	// on non ALU OpCodes
	InvalidALUOp ALUOp = 0xff
	// AddOp - addition
	AddOp ALUOp = 0x00
	// SubOp - subtraction
	SubOp ALUOp = 0x10
	// MulOp - multiplication
	MulOp ALUOp = 0x20
	// DivOp - division
	DivOp ALUOp = 0x30
	// OrOp - bitwise or
	OrOp ALUOp = 0x40
	// AndOp - bitwise and
	AndOp ALUOp = 0x50
	// LShOp - bitwise shift left
	LShOp ALUOp = 0x60
	// RShOp - bitwise shift right
	RShOp ALUOp = 0x70
	// NegOp - sign/unsign signing bit
	NegOp ALUOp = 0x80
	// ModOp - modulo
	ModOp ALUOp = 0x90
	// XOrOp - bitwise xor
	XOrOp ALUOp = 0xa0
	// MovOp - move value from one place to another; eBPF only.
	MovOp ALUOp = 0xb0
	// ArShOp - arithmatic shift; eBPF only.
	ArShOp ALUOp = 0xc0
	// EndOp - endian conversions; eBPF only
	EndOp ALUOp = 0xd0
)

// BranchOp affect control flow.
//
//    msb      lsb
//    +----+-+---+
//    |OP  |s|cls|
//    +----+-+---+
type BranchOp uint8

const branchMask OpCode = aluMask

const (
	// InvalidBranchOp is returned by getters when invoked
	// on non branch OpCodes
	InvalidBranchOp BranchOp = 0xff
	// JaOp to address
	JaOp BranchOp = 0x00
	// JEqOp to address if r == imm
	JEqOp BranchOp = 0x10
	// JGTOp to address if r > imm
	JGTOp BranchOp = 0x20
	// JGEOp to address if r >= imm
	JGEOp BranchOp = 0x30
	// JSETOp to address if signed r == signed imm
	JSETOp BranchOp = 0x40
	// JNEOp to address if r != imm, eBPF only
	JNEOp BranchOp = 0x50
	// JSGTOp to address if signed r > signed imm, eBPF only
	JSGTOp BranchOp = 0x60
	// JSGEOp to address if signed r >= signed imm, eBPF only
	JSGEOp BranchOp = 0x70
	// CallOp call into another BPF program, eBPF only
	CallOp BranchOp = 0x80
	// ExitOp exit program
	ExitOp BranchOp = 0x90
)

// OpCode is a packed eBPF opcode.
//
// Its encoding is defined by a Class value:
//
//    msb      lsb
//    +----+-+---+
//    | ???? |CLS|
//    +----+-+---+
type OpCode uint8

// InvalidOpCode is returned by setters on OpCode
const InvalidOpCode OpCode = 0xff

// Class returns the class of operation.
func (op OpCode) Class() Class {
	return Class(op & classMask)
}

func (op OpCode) Mode() Mode {
	if op.Class().encoding() != loadOrStore {
		return InvalidMode
	}
	return Mode(op & modeMask)
}

func (op OpCode) Size() Size {
	if op.Class().encoding() != loadOrStore {
		return InvalidSize
	}
	return Size(op & sizeMask)
}

func (op OpCode) Source() Source {
	if op.Class().encoding() != branchOrALU {
		return InvalidSource
	}
	return Source(op & sourceMask)
}

func (op OpCode) ALUOp() ALUOp {
	if op.Class().encoding() != branchOrALU {
		return InvalidALUOp
	}
	return ALUOp(op & aluMask)
}

func (op OpCode) BranchOp() BranchOp {
	if op.Class().encoding() != branchOrALU {
		return InvalidBranchOp
	}
	return BranchOp(op & branchMask)
}

// valid returns true if all bits in value are covered by mask.
func valid(value, mask OpCode) bool {
	return value & ^mask == 0
}
