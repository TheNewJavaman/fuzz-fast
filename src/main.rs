use crate::ptx::{
    PtxArrayOffset, PtxCmpOp, PtxInsn, PtxOpcode, PtxOperand, PtxPred, PtxStorage, PtxType,
};
use anyhow::{anyhow, Result};
use capstone::arch::x86;
use capstone::arch::x86::X86Insn::*;
use capstone::arch::x86::X86Reg::*;
use capstone::arch::x86::{X86Insn, X86OperandType};
use capstone::prelude::*;
use capstone::Insn;
use smallvec::smallvec;
use std::mem::transmute;

mod ptx;

const _PTX_TEMPLATE: &str = include_str!("template.ptx");

const CF: &str = "cf";
const ZF: &str = "zf";

const STACK: &str = "stack";

fn main() -> Result<()> {
    const CODE: & [u8] = b"\x55\x48\x89\xE5\x48\x89\x7D\xF8\x48\x89\x75\xF0\x48\xC7\x45\xD8\x00\x00\x00\x00\x48\x8B\x45\xD8\x48\x3B\x45\xF0\x73\x21\x48\x8B\x45\xF8\x48\x8B\x4D\xD8\x8A\x0C\x08\x48\x8B\x45\xD8\x88\x4C\x05\xE6\x48\x8B\x45\xD8\x48\x83\xC0\x01\x48\x89\x45\xD8\xEB\xD5\x66\xC7\x45\xD6\x00\x00\x48\xC7\x45\xC8\x00\x00\x00\x00\x48\x83\x7D\xC8\x05\x73\x21\x48\x8B\x45\xC8\x0F\xB6\x4C\x05\xE6\x0F\xB7\x45\xD6\x01\xC8\x66\x89\x45\xD6\x48\x8B\x45\xC8\x48\x83\xC0\x01\x48\x89\x45\xC8\xEB\xD8\x0F\xB7\x45\xD6\x5D\xC3";

    let cs = Capstone::new()
        .x86()
        .mode(x86::ArchMode::Mode64)
        .detail(true)
        .build()?;

    let mut ptx = vec![];
    for insn in cs.disasm_all(CODE, 0)?.as_ref() {
        println!("{}", insn);
        try_push_ptx(insn, &cs, &mut ptx)?;
    }

    Ok(())
}

pub fn try_push_ptx(insn: &Insn, cs: &Capstone, ptx: &mut Vec<PtxInsn>) -> Result<()> {
    let insn_detail = cs.insn_detail(insn)?;
    let arch_detail = insn_detail.arch_detail();
    let detail = arch_detail
        .x86()
        .ok_or(anyhow!("Failed to get instruction detail"))?;
    let mut operands = detail.operands();

    let matcher = (
        unsafe { transmute::<InsnId, X86Insn>(insn.id()) },
        operands.next().map(|o| o.op_type),
        operands.next().map(|o| o.op_type),
        operands.next().map(|o| o.op_type),
    );
    match matcher {
        (X86_INS_PUSH, Some(X86OperandType::Reg(src)), None, None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::Sub,
                uni: None,
                storage: None,
                cmp_op: None,
                bool_op: None,
                types: smallvec![PtxType::S64],
                operands: smallvec![
                    PtxOperand::Reg(reg_name(X86_REG_RSP, cs)?),
                    PtxOperand::Reg(reg_name(X86_REG_RSP, cs)?),
                    PtxOperand::Imm(reg_size(src) as i64)
                ],
            });
            ptx.push(PtxInsn {
                label: None,
                pred: None,
                opcode: PtxOpcode::St,
                uni: None,
                storage: Some(PtxStorage::Local),
                cmp_op: None,
                bool_op: None,
                types: smallvec![ptx_reg_type(src)],
                operands: smallvec![
                    PtxOperand::Array {
                        name: STACK.to_string(),
                        offsets: smallvec![PtxArrayOffset::Reg(reg_name(X86_REG_RSP, cs)?)]
                    },
                    PtxOperand::Reg(reg_name(src.0 as u32, cs)?),
                ],
            });
        }
        (X86_INS_MOV, Some(X86OperandType::Reg(dst)), Some(X86OperandType::Reg(src)), None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::Mov,
                uni: None,
                storage: None,
                cmp_op: None,
                bool_op: None,
                types: smallvec![ptx_reg_type(dst)],
                operands: smallvec![
                    PtxOperand::Reg(reg_name(dst.0 as u32, cs)?),
                    PtxOperand::Reg(reg_name(src.0 as u32, cs)?),
                ],
            });
        }
        (X86_INS_MOV, Some(X86OperandType::Reg(dst)), Some(X86OperandType::Imm(src)), None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::Mov,
                uni: None,
                storage: None,
                cmp_op: None,
                bool_op: None,
                types: smallvec![ptx_reg_type(dst)],
                operands: smallvec![
                    PtxOperand::Reg(reg_name(dst.0 as u32, cs)?),
                    PtxOperand::Imm(src),
                ],
            });
        }
        (X86_INS_MOV, Some(X86OperandType::Reg(dst)), Some(X86OperandType::Mem(src)), None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::Mov,
                uni: None,
                storage: None,
                cmp_op: None,
                bool_op: None,
                types: smallvec![ptx_reg_type(dst)],
                operands: smallvec![
                    PtxOperand::Reg(reg_name(dst.0 as u32, cs)?),
                    PtxOperand::Array {
                        name: STACK.to_string(),
                        offsets: smallvec![
                            PtxArrayOffset::Reg(reg_name(src.base().0 as u32, cs)?),
                            PtxArrayOffset::Imm(src.disp())
                        ]
                    },
                ],
            });
        }
        (X86_INS_MOV, Some(X86OperandType::Mem(dst)), Some(X86OperandType::Reg(src)), None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::St,
                uni: None,
                storage: Some(PtxStorage::Local),
                cmp_op: None,
                bool_op: None,
                types: smallvec![ptx_reg_type(src)],
                operands: smallvec![
                    PtxOperand::Array {
                        name: STACK.to_string(),
                        offsets: smallvec![
                            PtxArrayOffset::Reg(reg_name(dst.base().0 as u32, cs)?),
                            PtxArrayOffset::Imm(dst.disp())
                        ]
                    },
                    PtxOperand::Reg(reg_name(src.0 as u32, cs)?),
                ],
            });
        }
        (X86_INS_MOV, Some(X86OperandType::Mem(dst)), Some(X86OperandType::Imm(src)), None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::St,
                uni: None,
                storage: Some(PtxStorage::Local),
                cmp_op: None,
                bool_op: None,
                types: smallvec![PtxType::S64],
                operands: smallvec![
                    PtxOperand::Array {
                        name: STACK.to_string(),
                        offsets: smallvec![
                            PtxArrayOffset::Reg(reg_name(dst.base().0 as u32, cs)?),
                            PtxArrayOffset::Imm(dst.disp())
                        ]
                    },
                    PtxOperand::Imm(src),
                ],
            });
        }
        (X86_INS_CMP, Some(X86OperandType::Reg(lhs)), Some(X86OperandType::Mem(rhs)), None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::Setp,
                uni: None,
                storage: None,
                cmp_op: Some(PtxCmpOp::Lt),
                bool_op: None,
                types: smallvec![ptx_reg_type(lhs)],
                operands: smallvec![
                    PtxOperand::Reg(CF.to_string()),
                    PtxOperand::Reg(reg_name(lhs.0 as u32, cs)?),
                    PtxOperand::Array {
                        name: STACK.to_string(),
                        offsets: smallvec![
                            PtxArrayOffset::Reg(reg_name(rhs.base().0 as u32, cs)?),
                            PtxArrayOffset::Imm(rhs.disp())
                        ]
                    },
                ],
            });
            ptx.push(PtxInsn {
                label: None,
                pred: None,
                opcode: PtxOpcode::Setp,
                uni: None,
                storage: None,
                cmp_op: Some(PtxCmpOp::Eq),
                bool_op: None,
                types: smallvec![ptx_reg_type(lhs)],
                operands: smallvec![
                    PtxOperand::Reg(ZF.to_string()),
                    PtxOperand::Reg(reg_name(lhs.0 as u32, cs)?),
                    PtxOperand::Array {
                        name: STACK.to_string(),
                        offsets: smallvec![
                            PtxArrayOffset::Reg(reg_name(rhs.base().0 as u32, cs)?),
                            PtxArrayOffset::Imm(rhs.disp())
                        ]
                    },
                ],
            });
        }
        (X86_INS_CMP, Some(X86OperandType::Mem(lhs)), Some(X86OperandType::Imm(rhs)), None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::Setp,
                uni: None,
                storage: None,
                cmp_op: Some(PtxCmpOp::Lt),
                bool_op: None,
                types: smallvec![PtxType::S64],
                operands: smallvec![
                    PtxOperand::Reg(CF.to_string()),
                    PtxOperand::Array {
                        name: STACK.to_string(),
                        offsets: smallvec![
                            PtxArrayOffset::Reg(reg_name(lhs.base().0 as u32, cs)?),
                            PtxArrayOffset::Imm(lhs.disp())
                        ]
                    },
                    PtxOperand::Imm(rhs),
                ],
            });
            ptx.push(PtxInsn {
                label: None,
                pred: None,
                opcode: PtxOpcode::Setp,
                uni: None,
                storage: None,
                cmp_op: Some(PtxCmpOp::Eq),
                bool_op: None,
                types: smallvec![PtxType::S64],
                operands: smallvec![
                    PtxOperand::Reg(ZF.to_string()),
                    PtxOperand::Array {
                        name: STACK.to_string(),
                        offsets: smallvec![
                            PtxArrayOffset::Reg(reg_name(lhs.base().0 as u32, cs)?),
                            PtxArrayOffset::Imm(lhs.disp())
                        ]
                    },
                    PtxOperand::Imm(rhs),
                ],
            });
        }
        (X86_INS_JAE, Some(X86OperandType::Imm(dst)), None, None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: Some(PtxPred {
                    neg: true,
                    pred: CF.to_string(),
                }),
                opcode: PtxOpcode::Setp,
                uni: None,
                storage: None,
                cmp_op: None,
                bool_op: None,
                types: smallvec![PtxType::S64],
                operands: smallvec![PtxOperand::Reg(label_address(unsafe { transmute(dst) }))],
            });
        }
        (X86_INS_ADD, Some(X86OperandType::Reg(dst)), Some(X86OperandType::Imm(val)), None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::Add,
                uni: None,
                storage: None,
                cmp_op: None,
                bool_op: None,
                types: smallvec![PtxType::S64],
                operands: smallvec![
                    PtxOperand::Reg(reg_name(dst.0 as u32, cs)?),
                    PtxOperand::Imm(val)
                ],
            });
        }
        (X86_INS_JMP, Some(X86OperandType::Imm(dst)), None, None) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::Setp,
                uni: Some(()),
                storage: None,
                cmp_op: None,
                bool_op: None,
                types: smallvec![],
                operands: smallvec![PtxOperand::Reg(label_address(unsafe { transmute(dst) }))],
            });
        }
        (
            X86_INS_MOVZX,
            Some(X86OperandType::Reg(dst)),
            Some(X86OperandType::Mem(src)),
            None,
            None,
        ) => {
            ptx.push(PtxInsn {
                label: Some(label_address(insn.address())),
                pred: None,
                opcode: PtxOpcode::Mov,
                uni: None,
                storage: None,
                cmp_op: None,
                bool_op: None,
                types: smallvec![ptx_reg_type(dst)],
                operands: smallvec![
                    PtxOperand::Reg(reg_name(dst.0 as u32, cs)?),
                    PtxOperand::Array {
                        name: STACK.to_string(),
                        offsets: smallvec![
                            PtxArrayOffset::Reg(reg_name(src.base().0 as u32, cs)?),
                            PtxArrayOffset::Imm(src.disp())
                        ]
                    },
                ],
            });
        }
        _ => todo!(),
    }

    Ok(())
}

fn label_address(address: u64) -> String {
    format!("L{}", address)
}

fn ptx_reg_type(reg: RegId) -> PtxType {
    match reg_size(reg) {
        1 => PtxType::U8,
        2 => PtxType::U16,
        4 => PtxType::U32,
        8 => PtxType::U64,
        _ => todo!(),
    }
}

pub fn reg_size(reg: RegId) -> u8 {
    match reg.0 as u32 {
        X86_REG_AL | X86_REG_BL | X86_REG_CL | X86_REG_DL => 1,
        X86_REG_AX | X86_REG_BX | X86_REG_CX | X86_REG_DX => 2,
        X86_REG_EAX | X86_REG_EBX | X86_REG_ECX | X86_REG_EDX => 4,
        X86_REG_RAX | X86_REG_RBP | X86_REG_RBX | X86_REG_RCX | X86_REG_RDI | X86_REG_RDX
        | X86_REG_RIP | X86_REG_RIZ | X86_REG_RSI | X86_REG_RSP => 8,
        _ => todo!(),
    }
}

pub fn reg_name(reg: u32, cs: &Capstone) -> Result<String> {
    cs.reg_name(RegId(reg as RegIdInt))
        .ok_or(anyhow!("Failed to get register name"))
}
