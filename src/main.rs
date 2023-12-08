use std::arch::asm;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::mem;
use std::process::ExitCode;
use std::time::Instant;

use argon2::{Argon2, Block as Argon2Block};

// Output length of hash in bytes. Deliberately way too short.
// This makes recovering the original preimage literally impossible given a password with a
// reasonable amount of entropy.
const DIGEST_LEN: usize = 4;

const SALT_LEN: usize = 64;

// File format: binary file that contains the hash and salt, in that order, with no other data
const FILE_LEN: usize = DIGEST_LEN + SALT_LEN;

// This wrapper only exists so that we can let the return type of the real main function be bool.
//
// Don't use `exit()` anywhere in the program as it does not run the memory zeroing destructors.
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
    let input_file_data = read_file(file_path);

    let is_create: bool;
    let salt: &[u8];
    let mut new_salt = [0u8; SALT_LEN];

    // Only used when checking a digest against an existing file
    let mut expected_digest = [0u8; DIGEST_LEN];
    if let Some(ref input_file_data) = input_file_data {
        is_create = false;
        // using existing file
        salt = &input_file_data[DIGEST_LEN..(DIGEST_LEN + SALT_LEN)];
        expected_digest.copy_from_slice(&input_file_data[..DIGEST_LEN]);
    } else {
        // creating new file
        is_create = true;
        generate_salt(&mut new_salt);
        salt = &new_salt;
    }
    assert_eq!(salt.len(), SALT_LEN);

    if is_create {
        println!("Creating new file {}", file_path);
    } else {
        println!("Using file {}", file_path);
    }

    let (hasher, mut blocks) = init_argon2();

    // Is this necessary?
    // I think incorrect digests could theoretically be correlated against the correct digest and
    // leak data, but I'm not sure.
    let mut digest_buf = ZodBuf::new(DIGEST_LEN);
    let digest = digest_buf.get_mut();

    let mut password_1_buf: ZodBuf;
    let mut password_1: &[u8];

    // Creating new file
    if is_create {
        let password_1_len: usize;
        (password_1_buf, password_1_len) =
            read_password("Enter new password: ").expect("Error reading password");
        if password_1_len == 0 {
            println!("Empty password");
            return false;
        }
        password_1 = &password_1_buf.get()[..password_1_len];

        let (password_2_buf, password_2_len) =
            read_password("Enter new password again: ").expect("Error reading password");
        let password_2 = &password_2_buf.get()[..password_2_len];

        if !((password_1_len == password_2_len) && constant_time_equals(password_1, password_2)) {
            println!("Passwords do not match");
            return false;
        }

        hash_password(&hasher, &mut blocks, password_1, salt, digest);

        let mut output_file_data = [0u8; FILE_LEN];
        output_file_data[..DIGEST_LEN].copy_from_slice(digest);
        output_file_data[DIGEST_LEN..(DIGEST_LEN + SALT_LEN)].copy_from_slice(&new_salt);
        write_file(file_path, &output_file_data);
        println!("File {} created", file_path);
    } else {
        // Using existing file
        loop {
            let password_1_len: usize;
            (password_1_buf, password_1_len) =
                read_password("Enter password: ").expect("Error reading password");
            if password_1_len == 0 {
                return true;
            }
            password_1 = &password_1_buf.get()[..password_1_len];

            hash_password(&hasher, &mut blocks, password_1, salt, digest);
            if constant_time_equals(digest, &expected_digest) {
                println!("Password probably correct");
                break;
            } else {
                println!("Password incorrect");
            }
        }
    }

    // Password memorization practice after the correct password is in memory
    loop {
        let (password_n_buf, password_n_len) =
            read_password("Enter password: ").expect("Error reading password");
        if password_n_len == 0 {
            return true;
        }
        let password_n = &password_n_buf.get()[..password_n_len];

        if (password_1.len() == password_n_len) && constant_time_equals(password_1, password_n) {
            if is_create {
                // We know what the original password is and there is no chance of this being a
                // collision
                println!("Password correct");
            } else {
                println!("Password probably correct");
            }
        } else {
            if is_create {
                println!("Password incorrect");
            } else {
                println!("Password probably incorrect");
            }
        }
    }
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
        // Unread input in the kernel's stdin buffer is flushed when using TCSAFLUSH
        if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &termios) != 0 {
            return false;
        }
    }
    true
}

// Unexpected behavior may result if multiple objects exist at the same time
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
            // No good way to handle it here, since we might be unwinding.
            eprintln!("Failed to re-enable stdin echo");
        }
    }
}

fn init_argon2() -> (Argon2<'static>, ZodBlocks) {
    // These settings take about 1.0 seconds on my machine.
    //
    // It seems that in Argon2 parallelism *subdivides* the work instead of *multiplying* the work.
    // With the current single threaded code in the argon2 library, increasing P_COST does not
    // significantly change the execution time.
    //
    // TODO: increase these values when multithreading is added back to the argon2 library.
    // https://github.com/RustCrypto/password-hashes/issues/380
    const M_COST: u32 = 524288;
    const T_COST: u32 = 4;
    const P_COST: u32 = 1;

    let params = argon2::Params::new(M_COST, T_COST, P_COST, Some(DIGEST_LEN))
        .expect("Invalid Argon2 params");
    let hasher = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    (hasher, ZodBlocks::new(M_COST))
}

fn hash_password(
    hasher: &Argon2,
    blocks: &mut ZodBlocks,
    password: &[u8],
    salt: &[u8],
    digest: &mut [u8],
) {
    let start_time = Instant::now();
    hasher
        .hash_password_into_with_memory(password, salt, digest, blocks.get_mut())
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

struct ZodBlocks(Box<[Argon2Block]>);

impl ZodBlocks {
    fn new(len: u32) -> Self {
        // Should be optimized away in a release build
        assert_eq!(mem::size_of::<Argon2Block>(), 1024);
        assert!(mem::align_of::<Argon2Block>() >= 16);

        let len = len as usize;
        let mut blocks: Vec<Argon2Block> = Vec::with_capacity(len);
        blocks.resize(len, Argon2Block::new());
        Self(blocks.into_boxed_slice())
    }
    fn get_mut(&mut self) -> &mut [Argon2Block] {
        &mut self.0
    }
}

impl Drop for ZodBlocks {
    fn drop(&mut self) {
        let inner = self.get_mut();
        let byte_len = mem::size_of_val(inner);
        let ptr = inner.as_mut_ptr() as *mut u8;
        let bytes = unsafe { std::slice::from_raw_parts_mut(ptr, byte_len) };
        if cfg!(target_arch = "x86_64") {
            secure_zero_memory_aligned_16(bytes);
        } else {
            // Should error on an unsupported platform
            secure_zero_memory_aligned_4(bytes);
        }
    }
}

// Returns (buf, len), len includes newline character if one exists before EOF
fn secure_read_line(fd: libc::c_int) -> Option<(ZodBuf, usize)> {
    let mut buf = ZodBuf::new(256);
    let mut len: usize = 0;
    loop {
        // SAFETY: reading at most maxread bytes starting from the len-th byte of the buffer cannot
        // overflow
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
        assert!(nread as usize <= maxread);
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
    let range = buf.as_mut_ptr_range();
    let start = range.start as usize;
    let end = range.end as usize;
    unsafe {
        asm!("2:",
             "cmp {end}, {start}",
             "je 3f",
             "mov byte ptr [{start}], 0",
             "inc {start}",
             "jmp 2b",
             "3:",
             start = inout(reg) start => _,
             end = in(reg) end,
             options(nostack),
        );
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn secure_zero_memory_aligned_4(buf: &mut [u8]) {
    let range = buf.as_mut_ptr_range();
    let start = range.start as usize;
    let end = range.end as usize;
    assert!((start % 4 == 0) && (end % 4 == 0));
    unsafe {
        asm!("2:",
             "cmp {end}, {start}",
             "je 3f",
             "mov dword ptr [{start}], 0",
             "add {start}, 4",
             "jmp 2b",
             "3:",
             start = inout(reg) start => _,
             end = in(reg) end,
             options(nostack),
        );
    }
}

#[cfg(target_arch = "x86_64")]
fn secure_zero_memory_aligned_16(buf: &mut [u8]) {
    let range = buf.as_mut_ptr_range();
    let start = range.start as usize;
    let end = range.end as usize;
    assert!((start % 16 == 0) && (end % 16 == 0));
    unsafe {
        asm!("xorps {scratch}, {scratch}",
             "2:",
             "cmp {end}, {start}",
             "je 3f",
             "movaps [{start}], {scratch}",
             "add {start}, 16",
             "jmp 2b",
             "3:",
             start = inout(reg) start => _,
             end = in(reg) end,
             scratch = out(xmm_reg) _,
             options(nostack),
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
             "cmp {a_end}, {a}",
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
             options(nostack),
        );
        out == 0
    }
}
