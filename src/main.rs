use crate::ptx::{
    PtxArrayOffset, PtxCmpOp, PtxInsn, PtxOpcode, PtxOperand, PtxPred, PtxStorage, PtxType,
};
use anyhow::{anyhow, Result};
use capstone::arch::x86;
use capstone::arch::x86::X86Insn::*;
use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86Reg::*;
use capstone::arch::x86::{X86Insn, X86InsnDetail, X86Operand};
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

    let id: X86Insn = unsafe { transmute(insn.id().0) };
    match id {
        X86_INS_PUSH => {
            let src = get_operand(detail, 0)?;
            match src.op_type {
                X86OperandType::Reg(src) => {
                    ptx.push(PtxInsn {
                        label: Some(label_address(insn.address())),
                        pred: None,
                        opcode: PtxOpcode::Sub,
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
                _ => todo!(),
            }
        }
        X86_INS_MOV => {
            let dst = get_operand(detail, 0)?;
            let src = get_operand(detail, 1)?;
            match (dst.op_type, src.op_type) {
                (X86OperandType::Reg(dst), X86OperandType::Reg(src)) => {
                    ptx.push(PtxInsn {
                        label: Some(label_address(insn.address())),
                        pred: None,
                        opcode: PtxOpcode::Mov,
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
                (X86OperandType::Reg(dst), X86OperandType::Imm(src)) => {
                    ptx.push(PtxInsn {
                        label: Some(label_address(insn.address())),
                        pred: None,
                        opcode: PtxOpcode::Mov,
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
                (X86OperandType::Reg(dst), X86OperandType::Mem(src)) => {
                    ptx.push(PtxInsn {
                        label: Some(label_address(insn.address())),
                        pred: None,
                        opcode: PtxOpcode::Mov,
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
                (X86OperandType::Mem(dst), X86OperandType::Reg(src)) => {
                    ptx.push(PtxInsn {
                        label: Some(label_address(insn.address())),
                        pred: None,
                        opcode: PtxOpcode::St,
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
                (X86OperandType::Mem(dst), X86OperandType::Imm(src)) => {
                    ptx.push(PtxInsn {
                        label: Some(label_address(insn.address())),
                        pred: None,
                        opcode: PtxOpcode::St,
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
                _ => todo!(),
            }
        }
        X86_INS_CMP => {
            let lhs = get_operand(detail, 0)?;
            let rhs = get_operand(detail, 1)?;
            match (lhs.op_type, rhs.op_type) {
                (X86OperandType::Reg(lhs), X86OperandType::Mem(rhs)) => {
                    ptx.push(PtxInsn {
                        label: Some(label_address(insn.address())),
                        pred: None,
                        opcode: PtxOpcode::Setp,
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
                _ => todo!(),
            }
        }
        X86_INS_JAE => {
            let dst = get_operand(detail, 0)?;
            match dst.op_type {
                X86OperandType::Imm(dst) => {
                    ptx.push(PtxInsn {
                        label: Some(label_address(unsafe { transmute(dst) })),
                        pred: Some(PtxPred {
                            neg: true,
                            pred: CF.to_string(),
                        }),
                        opcode: PtxOpcode::Setp,
                        storage: None,
                        cmp_op: None,
                        bool_op: None,
                        types: smallvec![PtxType::S64],
                        operands: smallvec![PtxOperand::Reg(CF.to_string()), PtxOperand::Imm(dst),],
                    });
                }
                _ => todo!(),
            }
        }
        _ => todo!(),
    }

    Ok(())
}

fn get_operand(detail: &X86InsnDetail, n: usize) -> Result<X86Operand> {
    detail
        .operands()
        .nth(n)
        .ok_or(anyhow!("Failed to src operand"))
}

fn label_address(address: u64) -> String {
    format!("L{}", address)
}

fn ptx_reg_type(reg: RegId) -> PtxType {
    match reg_size(reg) {
        8 => PtxType::U64,
        _ => todo!(),
    }
}

pub fn reg_size(reg: RegId) -> u8 {
    match reg.0 as u32 {
        X86_REG_RAX | X86_REG_RBP | X86_REG_RBX | X86_REG_RCX | X86_REG_RDI | X86_REG_RDX
        | X86_REG_RIP | X86_REG_RIZ | X86_REG_RSI | X86_REG_RSP => 8,
        _ => todo!(),
    }
}

pub fn reg_name(reg: u32, cs: &Capstone) -> Result<String> {
    cs.reg_name(RegId(reg as RegIdInt))
        .ok_or(anyhow!("Failed to get register name"))
}
