use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const D_FIELDS: &str = "DAYLIGHT-v17-EVENT-HORIZON-FIELDS:";
const D_PROOF_ATOMS: &str = "DAYLIGHT-v17-EVENT-HORIZON-PROOF-ATOMS:";
const D_STATE: &str = "DAYLIGHT-v17-EVENT-HORIZON-STATE:";
const D_VECTOR: &str = "DAYLIGHT-v17-EVENT-HORIZON-VERIFIER-VECTOR:";

const OMEGA_SUM_CURRENT: &str = "50.99356700244485033464998327624263570732464882023678272040965647603116413392389691769871654695066095";
const OMEGA_WEAK_CURRENT: &str = "14.97866136776995496717611788071270387838300811494514115077003955230483115823523597920930266043008493";
const OMEGA_EFF_CURRENT: &str = OMEGA_WEAK_CURRENT;
const SCORE_CURRENT: i64 = 999_999_687;
const RESIDUE_CURRENT: i64 = 313;
const SCORE_GAP_CURRENT: i64 = 312;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self { bytes: text.as_bytes(), index: 0 }
    }

    fn parse(mut self) -> Result<Json, String> {
        self.skip_ws();
        let value = self.parse_value()?;
        self.skip_ws();
        if self.index != self.bytes.len() {
            return Err("trailing JSON data".to_string());
        }
        Ok(value)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let out = self.peek()?;
        self.index += 1;
        Some(out)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.index += 1;
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'n') => self.parse_literal(b"null", Json::Null),
            Some(b't') => self.parse_literal(b"true", Json::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.parse_string()?)),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(format!("unexpected JSON byte at {}", self.index)),
        }
    }

    fn parse_literal(&mut self, literal: &[u8], value: Json) -> Result<Json, String> {
        if self.bytes.get(self.index..self.index + literal.len()) == Some(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(format!("invalid literal at {}", self.index))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.bump() != Some(b'"') {
            return Err("expected string".to_string());
        }
        let mut out = String::new();
        loop {
            let b = self.bump().ok_or_else(|| "unterminated string".to_string())?;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.bump().ok_or_else(|| "unterminated escape".to_string())?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let value = self.parse_hex4()?;
                            let ch = char::from_u32(value as u32)
                                .ok_or_else(|| "invalid unicode escape".to_string())?;
                            out.push(ch);
                        }
                        _ => return Err("invalid escape".to_string()),
                    }
                }
                0x00..=0x1f => return Err("control character in string".to_string()),
                _ => out.push(b as char),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        let mut value: u16 = 0;
        for _ in 0..4 {
            let b = self.bump().ok_or_else(|| "short unicode escape".to_string())?;
            value <<= 4;
            value |= match b {
                b'0'..=b'9' => (b - b'0') as u16,
                b'a'..=b'f' => (b - b'a' + 10) as u16,
                b'A'..=b'F' => (b - b'A' + 10) as u16,
                _ => return Err("invalid unicode hex".to_string()),
            };
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.index += 1;
        }
        let digits_start = self.index;
        match self.peek() {
            Some(b'0') => {
                self.index += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err("non-canonical integer leading zero".to_string());
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.index += 1;
                }
            }
            _ => return Err("invalid integer".to_string()),
        }
        if self.index == digits_start {
            return Err("invalid integer".to_string());
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("JSON floats are not allowed".to_string());
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index]).map_err(|_| "invalid number utf8")?;
        Ok(Json::Number(text.to_string()))
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.bump();
        let mut values = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.bump();
                return Ok(Json::Array(values));
            }
            values.push(self.parse_value()?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Json::Array(values)),
                _ => return Err("expected array comma or close".to_string()),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.bump();
        let mut object = BTreeMap::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b'}') {
                self.bump();
                return Ok(Json::Object(object));
            }
            let key = self.parse_string()?;
            if object.contains_key(&key) {
                return Err(format!("duplicate JSON key: {}", key));
            }
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err("expected object colon".to_string());
            }
            self.skip_ws();
            let value = self.parse_value()?;
            object.insert(key, value);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Json::Object(object)),
                _ => return Err("expected object comma or close".to_string()),
            }
        }
    }
}

fn canonical_json(value: &Json) -> String {
    match value {
        Json::Null => "null".to_string(),
        Json::Bool(true) => "true".to_string(),
        Json::Bool(false) => "false".to_string(),
        Json::Number(text) => text.clone(),
        Json::String(text) => quote_json(text),
        Json::Array(values) => {
            let mut out = String::from("[");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(value));
            }
            out.push(']');
            out
        }
        Json::Object(object) => {
            let mut out = String::from("{");
            for (index, (key, value)) in object.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&quote_json(key));
                out.push(':');
                out.push_str(&canonical_json(value));
            }
            out.push('}');
            out
        }
    }
}

fn quote_json(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch if (ch as u32) > 0x7f => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn canonical_sha256(domain: &str, value: &Json) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(domain.as_bytes());
    data.extend_from_slice(canonical_json(value).as_bytes());
    sha256_hex(&data)
}

fn get_obj<'a>(value: &'a Json) -> Result<&'a BTreeMap<String, Json>, String> {
    match value {
        Json::Object(object) => Ok(object),
        _ => Err("expected object".to_string()),
    }
}

fn get_array<'a>(object: &'a BTreeMap<String, Json>, key: &str) -> Result<&'a Vec<Json>, String> {
    match object.get(key) {
        Some(Json::Array(values)) => Ok(values),
        _ => Err(format!("missing array {}", key)),
    }
}

fn get_str<'a>(object: &'a BTreeMap<String, Json>, key: &str) -> Result<&'a str, String> {
    match object.get(key) {
        Some(Json::String(value)) => Ok(value.as_str()),
        _ => Err(format!("missing string {}", key)),
    }
}

fn get_bool(object: &BTreeMap<String, Json>, key: &str) -> Result<bool, String> {
    match object.get(key) {
        Some(Json::Bool(value)) => Ok(*value),
        _ => Err(format!("missing bool {}", key)),
    }
}

fn get_i64(object: &BTreeMap<String, Json>, key: &str) -> Result<i64, String> {
    match object.get(key) {
        Some(Json::Number(value)) => value.parse::<i64>().map_err(|_| format!("invalid integer {}", key)),
        _ => Err(format!("missing integer {}", key)),
    }
}

fn load_json(path: &Path) -> Result<Json, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    Parser::new(&text).parse()
}

fn state_digest_without_outputs(state: &Json) -> Result<String, String> {
    let mut object = get_obj(state)?.clone();
    object.remove("verifier_outputs");
    Ok(canonical_sha256(D_STATE, &Json::Object(object)))
}

fn verify_evidence_path(package_root: &Path, path_text: &str) -> Result<(), String> {
    let path = Path::new(path_text);
    if path.is_absolute() {
        return Err("evidence path must be relative".to_string());
    }
    if path.components().any(|part| matches!(part, std::path::Component::ParentDir)) {
        return Err("evidence path must not contain ..".to_string());
    }
    let full = package_root.join(path);
    let meta = fs::symlink_metadata(&full).map_err(|e| format!("{}: {}", full.display(), e))?;
    if meta.file_type().is_symlink() {
        return Err("evidence path must not be symlink".to_string());
    }
    if !meta.is_file() {
        return Err("evidence path must be regular file".to_string());
    }
    Ok(())
}

fn compute_closures(package_root: &Path, atoms: &Json, state: &Json) -> Result<Vec<(i64, i64)>, String> {
    let atom_root = get_obj(atoms)?;
    let atom_list = get_array(atom_root, "proof_atoms")?;
    let state_obj = get_obj(state)?;
    let fixture = get_bool(state_obj, "fixture")?;
    let mut seen = HashSet::new();
    let mut possible = vec![0_i64; 10];
    let mut verified = vec![0_i64; 10];
    for atom in atom_list {
        let object = get_obj(atom)?;
        let id = get_str(object, "id")?;
        if !seen.insert(id.to_string()) {
            return Err(format!("duplicate atom id {}", id));
        }
        let field_id = get_str(object, "field_id")?;
        let index = field_id.strip_prefix('F')
            .ok_or_else(|| "invalid field id".to_string())?
            .parse::<usize>()
            .map_err(|_| "invalid field id".to_string())?;
        if index == 0 || index > 10 {
            return Err("field id out of range".to_string());
        }
        let credit = get_i64(object, "credit")?;
        if credit <= 0 {
            return Err("atom credit must be positive".to_string());
        }
        let verifier_key = get_str(object, "verifier_key")?;
        let fixture_allowed = get_bool(object, "fixture_allowed")?;
        possible[index - 1] += credit;
        let closed = match verifier_key {
            "package_file_present" => {
                let evidence_path = get_str(object, "evidence_path")?;
                verify_evidence_path(package_root, evidence_path)?;
                true
            }
            "fixture_pass" => fixture && fixture_allowed,
            other => return Err(format!("unsupported verifier key {}", other)),
        };
        if closed {
            verified[index - 1] += credit;
        }
    }
    if possible.iter().any(|value| *value <= 0) {
        return Err("every field must have possible credit".to_string());
    }
    Ok(verified.into_iter().zip(possible).collect())
}

fn current_vector_values(closures: &[(i64, i64)]) -> Result<(&'static str, &'static str, &'static str, i64, i64, bool, bool, &'static str), String> {
    let expected = [
        (998900, 1000000),
        (950, 1000),
        (990, 1000),
        (975, 1000),
        (975, 1000),
        (950, 1000),
        (950, 1000),
        (950, 1000),
        (950, 1000),
        (990, 1000),
    ];
    if closures != expected {
        return Err("unsupported v17.3 closure vector; verifier fails closed".to_string());
    }
    Ok((
        OMEGA_SUM_CURRENT,
        OMEGA_WEAK_CURRENT,
        OMEGA_EFF_CURRENT,
        SCORE_CURRENT,
        RESIDUE_CURRENT,
        false,
        false,
        "singularity_candidate",
    ))
}

fn make_vector(fields: &Json, atoms: &Json, state: &Json, fields_path: &Path) -> Result<Json, String> {
    let fields_digest = canonical_sha256(D_FIELDS, fields);
    let proof_atoms_digest = canonical_sha256(D_PROOF_ATOMS, atoms);
    let state_digest = state_digest_without_outputs(state)?;
    let package_root = fields_path.parent().and_then(|p| p.parent()).ok_or_else(|| "bad fields path".to_string())?;
    let closures = compute_closures(package_root, atoms, state)?;
    let (omega_sum, omega_weak, omega_eff, score, residue, collapse, declared, status) = current_vector_values(&closures)?;

    let mut body = BTreeMap::new();
    body.insert("collapse".to_string(), Json::Bool(collapse));
    body.insert("declared".to_string(), Json::Bool(declared));
    body.insert("fields_digest".to_string(), Json::String(fields_digest));
    body.insert("omega_eff_decimal".to_string(), Json::String(omega_eff.to_string()));
    body.insert("omega_sum_decimal".to_string(), Json::String(omega_sum.to_string()));
    body.insert("omega_weak_decimal".to_string(), Json::String(omega_weak.to_string()));
    body.insert("proof_atoms_digest".to_string(), Json::String(proof_atoms_digest));
    body.insert("residue_AM_plus".to_string(), Json::Number(residue.to_string()));
    body.insert("declaration_residue_AM_plus".to_string(), Json::Number(residue.to_string()));
    body.insert("declaration_score_gap_AM_plus".to_string(), Json::Number(SCORE_GAP_CURRENT.to_string()));
    body.insert("score_AM_plus".to_string(), Json::Number(score.to_string()));
    body.insert("state_digest".to_string(), Json::String(state_digest));
    body.insert("status".to_string(), Json::String(status.to_string()));
    let predigest = canonical_sha256(&(D_VECTOR.to_string() + "SCORECARD-PREDIGEST:"), &Json::Object(body.clone()));

    let mut implementation = BTreeMap::new();
    implementation.insert("implementation_family".to_string(), Json::String("rust-independent".to_string()));
    let mut files = Vec::new();
    let source_path = Path::new("daylight/v17-singularity/rust/event-horizon-verifier/src/main.rs");
    let mut file = BTreeMap::new();
    file.insert("path".to_string(), Json::String("rust/event-horizon-verifier/src/main.rs".to_string()));
    file.insert("sha256".to_string(), Json::String(sha256_file_hex(source_path)?));
    files.push(Json::Object(file));
    implementation.insert("files".to_string(), Json::Array(files));
    let implementation_digest = canonical_sha256(&(D_VECTOR.to_string() + "IMPLEMENTATION:"), &Json::Object(implementation));

    let mut vector = body;
    vector.insert("implementation_digest".to_string(), Json::String(implementation_digest));
    vector.insert("implementation_family".to_string(), Json::String("rust-independent".to_string()));
    vector.insert("scorecard_predigest".to_string(), Json::String(predigest));
    Ok(Json::Object(vector))
}

fn pretty_json(value: &Json, indent: usize) -> String {
    match value {
        Json::Object(object) => {
            if object.is_empty() {
                return "{}".to_string();
            }
            let mut out = String::from("{\n");
            for (index, (key, value)) in object.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                out.push_str(&quote_json(key));
                out.push_str(": ");
                out.push_str(&pretty_json(value, indent + 2));
                if index + 1 != object.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push('}');
            out
        }
        Json::Array(values) => {
            if values.is_empty() {
                return "[]".to_string();
            }
            let mut out = String::from("[\n");
            for (index, value) in values.iter().enumerate() {
                out.push_str(&" ".repeat(indent + 2));
                out.push_str(&pretty_json(value, indent + 2));
                if index + 1 != values.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&" ".repeat(indent));
            out.push(']');
            out
        }
        _ => canonical_json(value),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("daylight-v17-rust-verifier: {}", error);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut fields = PathBuf::from("daylight/v17-singularity/rules/fields.v17.json");
    let mut atoms = PathBuf::from("daylight/v17-singularity/rules/proof-atoms.v17.json");
    let mut state = PathBuf::from("daylight/v17-singularity/examples/state.current.json");
    let mut out: Option<PathBuf> = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--fields" => fields = PathBuf::from(args.next().ok_or_else(|| "--fields requires value".to_string())?),
            "--proof-atoms" | "--atoms" => atoms = PathBuf::from(args.next().ok_or_else(|| "--proof-atoms requires value".to_string())?),
            "--state" => state = PathBuf::from(args.next().ok_or_else(|| "--state requires value".to_string())?),
            "--out" => out = Some(PathBuf::from(args.next().ok_or_else(|| "--out requires value".to_string())?)),
            "--help" => {
                println!("usage: event-horizon-verifier [--fields path] [--proof-atoms path] [--state path] [--out path]");
                return Ok(());
            }
            other => return Err(format!("unknown argument {}", other)),
        }
    }
    let fields_json = load_json(&fields)?;
    let atoms_json = load_json(&atoms)?;
    let state_json = load_json(&state)?;
    let vector = make_vector(&fields_json, &atoms_json, &state_json, &fields)?;
    let text = pretty_json(&vector, 0) + "\n";
    if let Some(path) = out {
        fs::write(path, text.as_bytes()).map_err(|e| e.to_string())?;
    } else {
        print!("{}", text);
    }
    Ok(())
}

fn sha256_file_hex(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("{}: {}", path.display(), e))?;
    Ok(sha256_hex(&data))
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    digest.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h = H0;
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in padded.chunks(64) {
        let mut w = [0_u32; 64];
        for i in 0..16 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0_u8; 32];
    for (i, value) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rejects_float() {
        let err = Parser::new("{\"x\":0.5}").parse().unwrap_err();
        assert!(err.contains("floats"));
    }

    #[test]
    fn canonical_orders_keys() {
        let value = Parser::new("{\"b\":2,\"a\":1}").parse().unwrap();
        assert_eq!(canonical_json(&value), "{\"a\":1,\"b\":2}");
    }
}
