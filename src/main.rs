use std::arch::asm;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::mem;
use std::process::ExitCode;
use std::time::Instant;

use argon2::{Argon2, Block as Argon2Block};

// Output length of hash in bytes. Deliberately way too short.
// This makes recovering the original preimage basically impossible given a password with a
// reasonable amount of entropy.
const HASH_LEN: usize = 4;

const SALT_LEN: usize = 64;

// File format: binary file that contains the hash and salt in order with no other data
const FILE_LEN: usize = HASH_LEN + SALT_LEN;

// This wrapper only exists so the return type of the real main function can be bool.
//
// Don't use `exit()` anywhere in the program as that does not run the memory zeroing destructors.
// Panics are fine when set to unwind (not abort) because unwinding calls destructors.
fn main() -> ExitCode {
    if pwmem_main() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn pwmem_main() -> bool {
    if !disable_swap() {
        panic!("Error disabling swap with mlockall");
    }

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 || args[1].is_empty() {
        eprintln!("Usage: {} <file>", args[0]);
        return false;
    }
    let file_path: &str = &args[1];
    let file_data = read_file(file_path);
    let is_create = file_data.is_none();
    if is_create {
        println!("Creating new file {}", file_path);
    } else {
        println!("Using file {}", file_path);
    }
    // FIXME: remove
    assert!(is_create);

    let salt: &[u8];
    let mut new_salt = [0u8; SALT_LEN];
    let mut expected_hash = [0u8; HASH_LEN];
    if let Some(ref input_file_data) = file_data {
        // using existing file
        salt = &input_file_data[HASH_LEN..(HASH_LEN + SALT_LEN)];
        expected_hash.copy_from_slice(&input_file_data[..HASH_LEN]);
    } else {
        // creating new file
        generate_salt(&mut new_salt);
        salt = &new_salt;
    }
    assert_eq!(salt.len(), SALT_LEN);

    let (hasher, mut blocks) = init_argon2();
    let mut digest = [0u8; HASH_LEN];

    let (password_1_buf, password_1_len) =
        read_password("Enter new password: ").expect("Error reading password");
    if password_1_len == 0 {
        eprintln!("Passwords do not match");
        return false;
    }
    let password_1 = &password_1_buf.get()[..password_1_len];

    let (password_2_buf, password_2_len) =
        read_password("Enter new password again: ").expect("Error reading password");
    let password_2 = &password_2_buf.get()[..password_2_len];

    if (password_1_len != password_2_len) || !constant_time_equals(password_1, password_2) {
        eprintln!("Passwords do not match");
        return false;
    }

    hash_password(&hasher, &mut blocks, password_1, salt, &mut digest);

    let mut output_file_data = [0u8; FILE_LEN];
    output_file_data[..HASH_LEN].copy_from_slice(&digest);
    output_file_data[HASH_LEN..(HASH_LEN + SALT_LEN)].copy_from_slice(&new_salt);
    write_file(file_path, &output_file_data);
    println!("File {} created", file_path);

    true
}

fn disable_swap() -> bool {
    unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 }
}

fn read_file(file_path: &str) -> Option<Box<[u8]>> {
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                return None;
            }
            panic!("Error reading file {}: {}", file_path, err);
        }
    };
    let metadata = file.metadata().expect("Error reading file metadata");

    assert_eq!(
        metadata.len(),
        FILE_LEN as u64,
        "Expected file to be exactly {} bytes long",
        FILE_LEN
    );
    let mut ret = vec![0u8; FILE_LEN].into_boxed_slice();
    file.read_exact(&mut ret).expect("Error reading file data");
    Some(ret)
}

fn write_file(file_path: &str, data: &[u8]) {
    assert_eq!(data.len(), FILE_LEN);
    fs::write(file_path, data).expect("Error writing file");
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
            eprintln!("Failed to re-enable stdin echo");
        }
    }
}

fn init_argon2() -> (Argon2<'static>, Box<[Argon2Block]>) {
    // These settings take about 1.0 seconds on my machine.
    //
    // It seems that in Argon2 parallelism *subdivides* the work instead of *multiplying* the work.
    // With the current single threaded code, increasing P_COST does not significantly change the
    // running time.
    //
    // TODO: increase these values when multithreading is added back to the argon2 library.
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

fn hash_password(
    hasher: &Argon2,
    blocks: &mut [Argon2Block],
    password: &[u8],
    salt: &[u8],
    digest: &mut [u8],
) {
    let start_time = Instant::now();
    hasher
        .hash_password_into_with_memory(password, salt, digest, blocks)
        .expect("Error hashing password");
    let duration = start_time.elapsed();

    println!("Hash computed in {} ms", duration.as_millis());
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

fn read_password(prompt: &str) -> Option<(ZodBuf, usize)> {
    use std::io::Write;

    {
        let mut stdout = io::stdout();
        stdout.write_all(prompt.as_bytes()).unwrap();
        stdout.flush().unwrap();
    }

    let buf: ZodBuf;
    let mut len;
    {
        let disable_stdin_echo = DisableStdinEcho::new();
        (buf, len) = secure_read_line(libc::STDIN_FILENO)?;
        if len > 0 && buf.get()[len - 1] == b'\n' {
            len -= 1
        };
        drop(disable_stdin_echo);
    }

    io::stdout().write_all("\n".as_bytes()).unwrap();
    Some((buf, len))
}

fn generate_salt(buf: &mut [u8]) {
    File::open("/dev/urandom")
        .expect("Error opening /dev/urandom for salt generation")
        .read_exact(buf)
        .expect("Error reading salt bytes from /dev/urandom");
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn constant_time_equals(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    unsafe {
        let len = a.len();
        let a_start = a.as_ptr() as usize;
        let a_end = a_start + len;
        let b_start = b.as_ptr() as usize;
        let mut out: u8 = 0;
        asm!("2:",
             "cmp {a}, {a_end}",
             "je 3f",
             "mov {scratch}, byte ptr [{a}]",
             "xor {scratch}, byte ptr [{b}]",
             "or {out}, {scratch}",
             "inc {a}",
             "inc {b}",
             "jmp 2b",
             "3:",
             a = inout(reg) a_start => _,
             b = inout(reg) b_start => _,
             a_end = in(reg) a_end,
             scratch = out(reg_byte) _,
             out = inout(reg_byte) out,
        );
        out == 0
    }
}
