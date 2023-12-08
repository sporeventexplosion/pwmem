use std::arch::asm;
use std::mem;

use argon2::{Argon2, Block as Argon2Block};

// Output length of hash in bytes. Deliberately way too short.
// This makes recovering the original preimage basically impossible given a password with a
// reasonable amount of entropy.
const HASH_LEN: usize = 4;

const SALT_LEN: usize = 64;

fn main() {
    use std::time::Instant;

    if !disable_swap() {
        panic!("Disabling swap with mlockall failed");
    }

    let (hasher, mut blocks) = init_argon2();
    let mut output = [0u8; HASH_LEN];

    print!("Enter password: ");
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    let buf: ZodBuf;
    let input: &[u8];
    {
        let disable_stdin_echo = DisableStdinEcho::new();
        let mut len;
        (buf, len) = secure_read_line(libc::STDIN_FILENO).expect("Read input failed");
        if len > 0 && buf.get()[len - 1] == b'\n' {
            len -= 1
        };
        input = &buf.get()[..len];
        drop(disable_stdin_echo);
    }

    // FIXME: salt is bad
    let salt = [0xffu8; 64];

    let start_time = Instant::now();
    hasher
        .hash_password_into_with_memory(input, &salt, &mut output, &mut blocks)
        .expect("Hashing password failed");
    let duration = start_time.elapsed();

    println!("{:?}", output.as_slice());
    println!("Hashing took {} ms", duration.as_millis());
}

fn disable_swap() -> bool {
    unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 }
}

fn set_stdin_echo(do_echo: bool) -> bool {
    unsafe {
        let mut termios: libc::termios = mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut termios) != 0 {
            return false;
        }
        if do_echo {
            termios.c_lflag |= libc::ECHO;
        } else {
            termios.c_lflag &= !libc::ECHO;
        }
        // Unread input in stdin is flushed
        if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &termios) != 0 {
            return false;
        }
    }
    true
}

// Indeterminate behavior may result if multiple objects exist at the same time
#[must_use]
struct DisableStdinEcho {}

impl DisableStdinEcho {
    fn new() -> Option<Self> {
        if !set_stdin_echo(false) {
            return None;
        }
        Some(Self {})
    }
}

impl Drop for DisableStdinEcho {
    fn drop(&mut self) {
        if !set_stdin_echo(true) {
            // Should be very unlikely that disabling echo succeeded but re-enabling it fails.
            // No good way to handle it here.
            eprintln!("Re-enabling stdin echo failed");
        }
    }
}

fn init_argon2() -> (Argon2<'static>, Box<[Argon2Block]>) {
    // These settings take about 1.0 seconds on my machine.
    //
    // TODO: increase this value when multithreading is added back to the argon2 library.
    // https://github.com/RustCrypto/password-hashes/issues/380
    const M_COST: u32 = 49152;
    const T_COST: u32 = 2;
    const P_COST: u32 = 1;

    let params =
        argon2::Params::new(M_COST, T_COST, P_COST, Some(4)).expect("Invalid Argon2 params");
    let hasher = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut blocks: Vec<Argon2Block> = Vec::with_capacity(M_COST as usize);
    blocks.resize(M_COST as usize, Argon2Block::new());
    (hasher, blocks.into_boxed_slice())
}

fn get_digest(
    hasher: &Argon2,
    blocks: &mut [Argon2Block],
    input: &[u8],
    salt: &[u8],
    output: &[u8],
) {
}

// Zod: zero on drop
struct ZodBuf(Box<[u8]>);

impl ZodBuf {
    fn new(len: usize) -> Self {
        Self(vec![0u8; len].into_boxed_slice())
    }
    fn get(&self) -> &[u8] {
        &self.0
    }
    fn get_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn resize(&mut self, len: usize) {
        let mut other = Self::new(len);
        let old_len = self.len();
        let copy_len = old_len.min(len);
        let src = &self.get()[..copy_len];
        let dst = &mut other.get_mut()[..copy_len];
        dst.copy_from_slice(src);
        mem::swap(self, &mut other);
    }
}

impl Drop for ZodBuf {
    fn drop(&mut self) {
        secure_zero_memory(self.get_mut());
    }
}

// Returns (buf, len), len includes newline character if one exists before EOF
fn secure_read_line(fd: libc::c_int) -> Option<(ZodBuf, usize)> {
    let mut buf = ZodBuf::new(256);
    let mut len: usize = 0;
    loop {
        let maxread = buf.len() - len;
        let nread: isize;
        unsafe {
            nread = libc::read(
                fd,
                buf.get_mut()[len..].as_mut_ptr() as *mut libc::c_void,
                maxread,
            );
        };
        if nread < 0 {
            return None;
        }
        if nread == 0 {
            return Some((buf, len));
        }
        let mut i = len;
        len += nread as usize;
        while i < len {
            if buf.get()[i] == b'\n' {
                return Some((buf, i + 1));
            }
            i += 1;
        }
        if len == buf.len() {
            // The reallocation should panic if the buffer size gets too large
            buf.resize(len * 2);
        }
    }
}

// The program should refuse to compile on other architectures since this function would not exist.
//
// If you're really paranoid you need to care about stuff like write-back caches and the like, but
// since we can't touch kernel buffers I have doubts about whether it's worth it.
//
// This could be portably replaced with `write_volatile` + something like
// `atomic::compiler_fence(atomic::Ordering::SeqCst);`.
// See https://github.com/RustCrypto/utils/blob/master/zeroize/src/lib.rs
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn secure_zero_memory(buf: &mut [u8]) {
    unsafe {
        let range = buf.as_mut_ptr_range();
        let start = range.start as usize;
        let end = range.end as usize;
        // specifically zeroing 1 byte at a time for simplicity
        asm!("2:",
             "cmp {start}, {end}",
             "je 3f",
             "mov byte ptr [{start}], 0",
             "inc {start}",
             "jmp 2b",
             "3:",
             start = inout(reg) start => _,
             end = in(reg) end
        );
    }
}
