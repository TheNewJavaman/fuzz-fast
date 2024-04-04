use smallvec::SmallVec;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub struct PtxInsn {
    pub label: Option<String>,
    pub pred: Option<PtxPred>,
    pub opcode: PtxOpcode,
    pub storage: Option<PtxStorage>,
    pub cmp_op: Option<PtxCmpOp>,
    pub bool_op: Option<PtxBoolOp>,
    pub types: SmallVec<[PtxType; 2]>,
    pub operands: SmallVec<[PtxOperand; 4]>,
}

impl Display for PtxInsn {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        if let Some(label) = &self.label {
            write!(f, "{}: ", label)?;
        } else {
            write!(f, "    ")?;
        }
        write!(f, "{}", self.opcode)?;
        if let Some(storage) = &self.storage {
            write!(f, "{}", storage)?;
        }
        if let Some(cmp) = &self.cmp_op {
            write!(f, "{}", cmp)?;
        }
        if let Some(bool_op) = &self.bool_op {
            write!(f, "{}", bool_op)?;
        }
        for ty in &self.types {
            write!(f, "{}", ty)?;
        }
        for (idx, op) in self.operands.iter().enumerate() {
            if idx == 0 {
                write!(f, " {}", op)?;
            } else {
                write!(f, ", {}", op)?;
            }
        }
        write!(f, ";")?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct PtxPred {
    pub neg: bool,
    pub pred: String,
}

impl Display for PtxPred {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "@")?;
        if self.neg {
            write!(f, "!")?;
        }
        write!(f, "{}", self.pred)
    }
}

#[derive(Debug)]
pub enum PtxOpcode {
    Add,
    Sub,
    Mov,
    Ld,
    St,
    Setp,
}

impl Display for PtxOpcode {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PtxOpcode::Add => write!(f, "add"),
            PtxOpcode::Sub => write!(f, "sub"),
            PtxOpcode::Mov => write!(f, "mov"),
            PtxOpcode::Ld => write!(f, "ld"),
            PtxOpcode::St => write!(f, "st"),
            PtxOpcode::Setp => write!(f, "setp"),
        }
    }
}

#[derive(Debug)]
pub enum PtxStorage {
    Reg,
    Sreg,
    Const,
    Global,
    Local,
    Param,
    Shared,
    Tex,
}

impl Display for PtxStorage {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PtxStorage::Reg => write!(f, ".reg"),
            PtxStorage::Sreg => write!(f, ".sreg"),
            PtxStorage::Const => write!(f, ".const"),
            PtxStorage::Global => write!(f, ".global"),
            PtxStorage::Local => write!(f, ".local"),
            PtxStorage::Param => write!(f, ".param"),
            PtxStorage::Shared => write!(f, ".shared"),
            PtxStorage::Tex => write!(f, ".tex"),
        }
    }
}

#[derive(Debug)]
pub enum PtxCmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Lo,
    Ls,
    Hi,
    Hs,
}

impl Display for PtxCmpOp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PtxCmpOp::Eq => write!(f, ".eq"),
            PtxCmpOp::Ne => write!(f, ".ne"),
            PtxCmpOp::Lt => write!(f, ".lt"),
            PtxCmpOp::Le => write!(f, ".le"),
            PtxCmpOp::Gt => write!(f, ".gt"),
            PtxCmpOp::Ge => write!(f, ".ge"),
            PtxCmpOp::Lo => write!(f, ".lo"),
            PtxCmpOp::Ls => write!(f, ".ls"),
            PtxCmpOp::Hi => write!(f, ".hi"),
            PtxCmpOp::Hs => write!(f, ".hs"),
        }
    }
}

#[derive(Debug)]
pub enum PtxBoolOp {
    And,
    Or,
    Xor,
}

impl Display for PtxBoolOp {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PtxBoolOp::And => write!(f, ".and"),
            PtxBoolOp::Or => write!(f, ".or"),
            PtxBoolOp::Xor => write!(f, ".xor"),
        }
    }
}

#[derive(Debug)]
pub enum PtxType {
    B8,
    B16,
    B32,
    B64,
    B128,
    S8,
    S16,
    S32,
    S64,
    U8,
    U16,
    U32,
    U64,
    F16,
    F32,
    F64,
}

impl Display for PtxType {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PtxType::B8 => write!(f, ".b8"),
            PtxType::B16 => write!(f, ".b16"),
            PtxType::B32 => write!(f, ".b32"),
            PtxType::B64 => write!(f, ".b64"),
            PtxType::B128 => write!(f, ".b128"),
            PtxType::S8 => write!(f, ".s8"),
            PtxType::S16 => write!(f, ".s16"),
            PtxType::S32 => write!(f, ".s32"),
            PtxType::S64 => write!(f, ".s64"),
            PtxType::U8 => write!(f, ".u8"),
            PtxType::U16 => write!(f, ".u16"),
            PtxType::U32 => write!(f, ".u32"),
            PtxType::U64 => write!(f, ".u64"),
            PtxType::F16 => write!(f, ".f16"),
            PtxType::F32 => write!(f, ".f32"),
            PtxType::F64 => write!(f, ".f64"),
        }
    }
}

#[derive(Debug)]
pub enum PtxOperand {
    Reg(String),
    Imm(i64),
    Array {
        name: String,
        offsets: SmallVec<[PtxArrayOffset; 2]>,
    },
}

impl Display for PtxOperand {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PtxOperand::Reg(reg) => write!(f, "{}", reg),
            PtxOperand::Imm(imm) => write!(f, "{}", imm),
            PtxOperand::Array { name, offsets } => {
                write!(f, "[{}", name)?;
                for offset in offsets {
                    write!(f, " + {}", offset)?;
                }
                write!(f, "]")
            }
        }
    }
}

#[derive(Debug)]
pub enum PtxArrayOffset {
    Reg(String),
    Imm(i64),
}

impl Display for PtxArrayOffset {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PtxArrayOffset::Reg(reg) => write!(f, "{}", reg),
            PtxArrayOffset::Imm(imm) => write!(f, "{}", imm),
        }
    }
}
