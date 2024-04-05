use anyhow::{anyhow, Result};
use capstone::arch::x86::X86Insn::*;
use capstone::arch::x86::X86Reg::*;
use capstone::arch::x86::{self, X86OpMem};
use capstone::arch::x86::{X86Insn, X86OperandType};
use capstone::prelude::*;
use capstone::Insn;
use std::mem::transmute;

const _PTX_TEMPLATE: &str = include_str!("template.ptx");

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

    for line in ptx {
        println!("{}", line);
    }

    Ok(())
}

pub fn try_push_ptx(insn: &Insn, cs: &Capstone, ptx: &mut Vec<String>) -> Result<()> {
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
            ptx.push(format!(
                "L_{:X}:\tsub.u64 rsp, rsp, {};",
                insn.address(),
                reg_size(src)
            ));
            ptx.push(format!(
                "\tst.local.{} [stack + rsp], {};",
                reg_uint_type(src),
                reg_name(src)
            ));
        }
        (X86_INS_MOV, Some(X86OperandType::Reg(dst)), Some(X86OperandType::Reg(src)), None) => {
            ptx.push(format!(
                "L_{:X}:\tmov.{} {}, {};",
                insn.address(),
                reg_uint_type(dst),
                reg_name(dst),
                reg_name(src)
            ));
        }
        (X86_INS_MOV, Some(X86OperandType::Reg(dst)), Some(X86OperandType::Imm(src)), None) => {
            ptx.push(format!(
                "L_{:X}:\tmov.{} {}, {};",
                insn.address(),
                reg_sint_type(dst),
                reg_name(dst),
                src
            ));
        }
        (X86_INS_MOV, Some(X86OperandType::Reg(dst)), Some(X86OperandType::Mem(src)), None) => {
            ptx.push(format!(
                "L_{:X}:\tld.local.{} {}, {};",
                insn.address(),
                reg_uint_type(dst),
                reg_name(dst),
                format_mem(&src)
            ));
        }
        (X86_INS_MOV, Some(X86OperandType::Mem(dst)), Some(X86OperandType::Reg(src)), None) => {
            ptx.push(format!(
                "L_{:X}:\tst.local.{} {}, {};",
                insn.address(),
                reg_uint_type(src),
                format_mem(&dst),
                reg_name(src)
            ));
        }
        (X86_INS_MOV, Some(X86OperandType::Mem(dst)), Some(X86OperandType::Imm(src)), None) => {
            ptx.push(format!(
                "L_{:X}:\tst.local.s64 {}, {};",
                insn.address(),
                format_mem(&dst),
                src
            ));
        }
        (X86_INS_CMP, Some(X86OperandType::Reg(lhs)), Some(X86OperandType::Mem(rhs)), None) => {
            ptx.push(format!(
                "L_{:X}:\tsetp.lt.{} cf, {}, {};",
                insn.address(),
                reg_sint_type(lhs),
                reg_name(lhs),
                format_mem(&rhs)
            ));
            ptx.push(format!(
                "\tsetp.eq.{} zf, {}, {};",
                reg_sint_type(lhs),
                reg_name(lhs),
                format_mem(&rhs)
            ));
        }
        (X86_INS_CMP, Some(X86OperandType::Mem(lhs)), Some(X86OperandType::Imm(rhs)), None) => {
            ptx.push(format!(
                "L_{:X}:\tsetp.lt.s64 cf, {}, {};",
                insn.address(),
                format_mem(&lhs),
                rhs
            ));
            ptx.push(format!(
                "\tsetp.eq.s64 zf, {}, {};",
                format_mem(&lhs),
                rhs
            ));
        }
        (X86_INS_JAE, Some(X86OperandType::Imm(dst)), None, None) => {
            ptx.push(format!("L_{:X}:\t@!cf bra L_{:X};", insn.address(), dst));
        }
        (X86_INS_ADD, Some(X86OperandType::Reg(dst)), Some(X86OperandType::Imm(val)), None) => {
            ptx.push(format!(
                "L_{:X}:\tadd.s64 {}, {}, {};",
                insn.address(),
                reg_name(dst),
                reg_name(dst),
                val
            ));
        }
        (X86_INS_JMP, Some(X86OperandType::Imm(dst)), None, None) => {
            ptx.push(format!("L_{:X}:\tbra.uni L_{:X};", insn.address(), dst));
        }
        // (
        //     X86_INS_MOVZX,
        //     Some(X86OperandType::Reg(dst)),
        //     Some(X86OperandType::Mem(src)),
        //     None,
        // ) => {
        //     ptx.push(PtxInsn {
        //         label: Some(label_address(insn.address())),
        //         pred: None,
        //         opcode: PtxOpcode::Mov,
        //         uni: None,
        //         storage: None,
        //         cmp_op: None,
        //         bool_op: None,
        //         types: smallvec![ptx_reg_type(dst)],
        //         operands: smallvec![
        //             PtxOperand::Reg(reg_name(dst.0 as u32, cs)?),
        //             PtxOperand::Array {
        //                 name: STACK.to_string(),
        //                 offsets: smallvec![
        //                     PtxArrayOffset::Reg(reg_name(src.base().0 as u32, cs)?),
        //                     PtxArrayOffset::Imm(src.disp())
        //                 ]
        //             },
        //         ],
        //     });
        // }
        _ => todo!(),
    }

    Ok(())
}

fn reg_uint_type(reg: RegId) -> &'static str {
    match reg_size(reg) {
        1 => "u8",
        2 => "u16",
        4 => "u32",
        8 => "u64",
        _ => todo!(),
    }
}

fn reg_sint_type(reg: RegId) -> &'static str {
    match reg_size(reg) {
        1 => "s8",
        2 => "s16",
        4 => "s32",
        8 => "s64",
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

pub fn reg_name(reg: RegId) -> &'static str {
    match reg.0 as u32 {
        X86_REG_AL => "al",
        X86_REG_BL => "bl",
        X86_REG_CL => "cl",
        X86_REG_DL => "dl",
        X86_REG_AX => "ax",
        X86_REG_BX => "bx",
        X86_REG_CX => "cx",
        X86_REG_DX => "dx",
        X86_REG_EAX => "eax",
        X86_REG_EBX => "ebx",
        X86_REG_ECX => "ecx",
        X86_REG_EDX => "edx",
        X86_REG_RAX => "rax",
        X86_REG_RBX => "rbx",
        X86_REG_RCX => "rcx",
        X86_REG_RDX => "rdx",
        X86_REG_RIP => "rip",
        X86_REG_RSI => "rsi",
        X86_REG_RBP => "rbp",
        X86_REG_RDI => "rdi",
        X86_REG_RSP => "rsp",
        _ => todo!(),
    }
}

fn format_mem(mem: &X86OpMem) -> String {
    if mem.base().0 as u32 == X86_REG_INVALID {
        format!("[stack + {}]", mem.disp())
    } else {
        format!("[stack + {} + {}]", reg_name(mem.base()), mem.disp())
    }
}
