use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use memmap2::Mmap;
use anyhow::Result;

pub enum FileContent {
    Heap(Vec<u8>),
    Mmap(Mmap),
}

impl std::ops::Deref for FileContent {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            FileContent::Heap(v) => v,
            FileContent::Mmap(m) => m,
        }
    }
}

pub struct FileLoader;

impl FileLoader {
    const MMAP_THRESHOLD: u64 = 10 * 1024 * 1024;  // 10MB
    const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;  // 100MB limit
    const SAMPLE_SIZE: usize = 8192;               // 8KB sample for detection

    // Magic bytes for common binary formats
    const MAGIC_BYTES: &'static [(&'static [u8], &'static str)] = &[
        // Images
        (&[0x89, 0x50, 0x4E, 0x47], "PNG"),
        (&[0xFF, 0xD8, 0xFF], "JPEG"),
        (&[0x47, 0x49, 0x46, 0x38], "GIF"),
        (&[0x42, 0x4D], "BMP"),
        (&[0x00, 0x00, 0x01, 0x00], "ICO"),
        (&[0x52, 0x49, 0x46, 0x46], "WEBP/AVI"),

        // Archives
        (&[0x50, 0x4B, 0x03, 0x04], "ZIP/DOCX/JAR"),
        (&[0x50, 0x4B, 0x05, 0x06], "ZIP empty"),
        (&[0x1F, 0x8B], "GZIP"),
        (&[0x42, 0x5A, 0x68], "BZIP2"),
        (&[0xFD, 0x37, 0x7A, 0x58, 0x5A], "XZ"),
        (&[0x52, 0x61, 0x72, 0x21], "RAR"),
        (&[0x37, 0x7A, 0xBC, 0xAF], "7Z"),

        // Executables
        (&[0x7F, 0x45, 0x4C, 0x46], "ELF"),
        (&[0x4D, 0x5A], "EXE/DLL"),
        (&[0xCF, 0xFA, 0xED, 0xFE], "Mach-O 64"),
        (&[0xCE, 0xFA, 0xED, 0xFE], "Mach-O 32"),
        (&[0xCA, 0xFE, 0xBA, 0xBE], "Java class/Fat Mach-O"),

        // Documents
        (&[0x25, 0x50, 0x44, 0x46], "PDF"),
        (&[0xD0, 0xCF, 0x11, 0xE0], "MS Office old"),

        // Media
        (&[0x49, 0x44, 0x33], "MP3"),
        (&[0xFF, 0xFB], "MP3"),
        (&[0x00, 0x00, 0x00, 0x1C, 0x66, 0x74, 0x79, 0x70], "MP4"),
        (&[0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70], "MP4"),
        (&[0x4F, 0x67, 0x67, 0x53], "OGG"),
        (&[0x1A, 0x45, 0xDF, 0xA3], "WebM/MKV"),

        // Fonts
        (&[0x00, 0x01, 0x00, 0x00], "TrueType font"),
        (&[0x4F, 0x54, 0x54, 0x4F], "OpenType font"),
        (&[0x77, 0x4F, 0x46, 0x46], "WOFF"),
        (&[0x77, 0x4F, 0x46, 0x32], "WOFF2"),

        // Databases
        (&[0x53, 0x51, 0x4C, 0x69, 0x74, 0x65], "SQLite"),

        // Other
        (&[0x00, 0x61, 0x73, 0x6D], "WebAssembly"),
    ];

    pub fn load(path: &Path) -> Result<FileContent> {
        let mut file = File::open(path)?;
        let metadata = file.metadata()?;
        let size = metadata.len();

        if size == 0 {
            return Ok(FileContent::Heap(Vec::new()));
        }

        // Skip files larger than 100MB to prevent OOM
        if size > Self::MAX_FILE_SIZE {
            return Err(anyhow::anyhow!("File too large: {} bytes", size));
        }

        // Read sample for binary detection
        let sample_size = std::cmp::min(size as usize, Self::SAMPLE_SIZE);
        let mut sample = vec![0u8; sample_size];
        file.read_exact(&mut sample)?;

        // Check if binary using multiple heuristics
        if Self::is_binary(&sample) {
            return Err(anyhow::anyhow!("Binary file detected"));
        }

        // Reset file cursor
        file.seek(SeekFrom::Start(0))?;

        if size > Self::MMAP_THRESHOLD {
            // Unsafe: We accept the risk of SIGBUS if file is truncated.
            unsafe {
                let mmap = memmap2::MmapOptions::new().map(&file)?;
                Ok(FileContent::Mmap(mmap))
            }
        } else {
            let mut buffer = Vec::with_capacity(size as usize);
            file.read_to_end(&mut buffer)?;
            Ok(FileContent::Heap(buffer))
        }
    }

    fn is_binary(sample: &[u8]) -> bool {
        if sample.is_empty() {
            return false;
        }

        // 1. Check magic bytes first (most reliable)
        for (magic, _name) in Self::MAGIC_BYTES {
            if sample.len() >= magic.len() && sample.starts_with(magic) {
                return true;
            }
        }

        // 2. Check for UTF-16/UTF-32 BOM (valid text, not binary)
        if Self::has_unicode_bom(sample) {
            return false;
        }

        // 3. Heuristic: Count control characters and null bytes
        let mut null_count = 0;
        let mut control_count = 0;
        let mut high_byte_count = 0;
        let check_len = std::cmp::min(sample.len(), 4096);

        for &byte in &sample[..check_len] {
            match byte {
                0x00 => null_count += 1,
                // Control chars except common ones (tab, newline, carriage return)
                0x01..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F => control_count += 1,
                // High bytes (could be UTF-8 or binary)
                0x80..=0xFF => high_byte_count += 1,
                _ => {}
            }
        }

        // Binary if >1% null bytes (UTF-16 would have ~50% but we handle BOM)
        let null_ratio = null_count as f64 / check_len as f64;
        if null_ratio > 0.01 {
            return true;
        }

        // Binary if >10% control characters
        let control_ratio = control_count as f64 / check_len as f64;
        if control_ratio > 0.10 {
            return true;
        }

        // 4. Check if valid UTF-8 with high bytes (likely text)
        if high_byte_count > 0 {
            // If it parses as valid UTF-8, it's probably text
            if std::str::from_utf8(sample).is_ok() {
                return false;
            }
            // Invalid UTF-8 with many high bytes = likely binary
            let high_ratio = high_byte_count as f64 / check_len as f64;
            if high_ratio > 0.30 {
                return true;
            }
        }

        false
    }

    fn has_unicode_bom(sample: &[u8]) -> bool {
        // UTF-8 BOM
        if sample.len() >= 3 && sample[..3] == [0xEF, 0xBB, 0xBF] {
            return true;
        }
        // UTF-16 LE BOM
        if sample.len() >= 2 && sample[..2] == [0xFF, 0xFE] {
            return true;
        }
        // UTF-16 BE BOM
        if sample.len() >= 2 && sample[..2] == [0xFE, 0xFF] {
            return true;
        }
        // UTF-32 LE BOM
        if sample.len() >= 4 && sample[..4] == [0xFF, 0xFE, 0x00, 0x00] {
            return true;
        }
        // UTF-32 BE BOM
        if sample.len() >= 4 && sample[..4] == [0x00, 0x00, 0xFE, 0xFF] {
            return true;
        }
        false
    }
}
