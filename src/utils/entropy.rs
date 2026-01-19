/// Calculate Shannon Entropy for a byte slice.
/// Returns a value between 0.0 and 8.0.
/// 
/// High entropy (> 4.5) often indicates randomness (keys, encrypted strings).
/// Normal text usually has entropy < 3.5-4.0.
pub fn calculate_shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0u32; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy = 0.0;

    for &count in frequencies.iter() {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Tokenizes content into potential credential candidates.
/// Simple heuristic: Split by whitespace/quotes/assignment.
pub fn find_high_entropy_tokens(content: &[u8], threshold: f32) -> Vec<(String, f32)> {
    // For performance, we can do a single pass or use `split`.
    // We'll treat any sequence of alphanumeric chars > 20 as a candidate.
    
    let mut results = Vec::new();
    let text = String::from_utf8_lossy(content);
    
    // Split by common delimiters
    let tokens = text.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-');

    for token in tokens {
        if token.len() > 20 && token.len() < 128 { // Reasonable bounds for a secret
            let entropy = calculate_shannon_entropy(token.as_bytes());
            if entropy > threshold {
                 results.push((token.to_string(), entropy));
            }
        }
    }

    results
}
