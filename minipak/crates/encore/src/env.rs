//! Utilities for reading things from the process's environment.

use crate::utils::NullTerminated;
use alloc::vec::Vec;
use core::fmt;

/// An auxiliary vector.
#[repr(C)]
pub struct Auxv {
    pub typ: AuxvType,
    pub value: u64,
}

impl fmt::Debug for Auxv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AT_{:?} = 0x{:x}", self.typ, self.value)
    }
}

/// The type of an auxiliary vector.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct AuxvType(u64);

impl AuxvType {
    /// Marks the end of an auxiliary vector list.
    pub const NULL: Self = Self(0);
    /// Address of the first program header in memory.
    pub const PHDR: Self = Self(3);
    /// Number of program headers.
    pub const PHNUM: Self = Self(5);
    /// Address where the interpreter (dynamic loader) is mapped.
    pub const BASE: Self = Self(7);
    /// Entry point of the program.
    pub const ENTRY: Self = Self(9);
}

impl fmt::Debug for AuxvType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::PHDR => "PHDR",
            Self::PHNUM => "PHNUM",
            Self::BASE => "BASE",
            Self::ENTRY => "ENTRY",
            _ => "(UNKNOWN)",
        })
    }
}

/// A program's environment.
#[derive(Default)]
pub struct Env {
    /// Auxiliary vectors.
    pub vectors: Vec<&'static mut Auxv>,
    /// Command-line arguments.
    pub args: Vec<&'static str>,
    /// Environment variables
    pub vars: Vec<&'static str>,
}

impl Env {
    /// Read the current process's environment into a struct.
    ///
    /// # Safety
    /// Walks the stack starting from `stack_top`, which isn't really that safe.
    pub unsafe fn read(stack_top: *mut u8) -> Self {
        let mut ptr: *mut u64 = stack_top as _;

        let mut env = Self::default();

        // Read arguments
        ptr = ptr.add(1);
        while *ptr != 0 {
            let arg = (*ptr as *const u8).cstr();
            env.args.push(arg);
            ptr = ptr.add(1);
        }

        // Read environment variables
        ptr = ptr.add(1);
        while *ptr != 0 {
            let var = (*ptr as *const u8).cstr();
            env.vars.push(var);
            ptr = ptr.add(1);
        }

        // Read auxiliary vectors
        ptr = ptr.add(1);
        let mut ptr: *mut Auxv = ptr as _;
        while (*ptr).typ != AuxvType::NULL {
            env.vectors.push(ptr.as_mut().unwrap());
            ptr = ptr.add(1);
        }

        env
    }

    /// Finds an auxiliary vector by type. Panics if it cannot be found.
    pub fn find_vector(&mut self, typ: AuxvType) -> &mut Auxv {
        self.vectors
            .iter_mut()
            .find(|v| v.typ == typ)
            .unwrap_or_else(|| panic!("aux vector {:?} not found", typ))
    }
}
