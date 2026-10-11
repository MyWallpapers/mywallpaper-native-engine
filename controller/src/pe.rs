use std::path::Path;

pub(crate) struct Image<'a> {
    bytes: &'a [u8],
    pub nt: usize,
    pub optional: usize,
    sections: usize,
    count: usize,
}
impl<'a> Image<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.get(..2) != Some(b"MZ") {
            return Err("not a PE image".to_owned());
        }
        let nt = u32_at(bytes, 0x3c)? as usize;
        if bytes.get(nt..nt + 4) != Some(b"PE\0\0") {
            return Err("PE signature is missing".to_owned());
        }
        let count = u16_at(bytes, nt + 6)? as usize;
        let size = u16_at(bytes, nt + 20)? as usize;
        let optional = nt + 24;
        if !matches!(u16_at(bytes, optional)?, 0x10b | 0x20b) {
            return Err("unsupported PE optional header".to_owned());
        }
        let sections = optional.checked_add(size).ok_or("PE size overflow")?;
        if sections + count * 40 > bytes.len() {
            return Err("truncated PE sections".to_owned());
        }
        Ok(Self {
            bytes,
            nt,
            optional,
            sections,
            count,
        })
    }
    pub fn entry_rva(&self) -> Result<u32, String> {
        u32_at(self.bytes, self.optional + 16)
    }
    fn offset(&self, rva: u32) -> Result<usize, String> {
        for index in 0..self.count {
            let section = self.sections + index * 40;
            let address = u32_at(self.bytes, section + 12)?;
            let raw_size = u32_at(self.bytes, section + 16)?;
            if rva >= address && rva - address < raw_size {
                return Ok((u32_at(self.bytes, section + 20)? as usize) + (rva - address) as usize);
            }
        }
        Err("PE RVA has no file-backed section".to_owned())
    }
    pub fn symbol_request(
        &self,
        path: &Path,
        name: &str,
    ) -> Result<crate::symbols::SymbolRequest, String> {
        let directories = self.optional
            + if u16_at(self.bytes, self.optional)? == 0x20b {
                112
            } else {
                96
            };
        let debug_rva = u32_at(self.bytes, directories + 6 * 8)?;
        let debug_size = u32_at(self.bytes, directories + 6 * 8 + 4)?;
        let debug = self.offset(debug_rva)?;
        for index in 0..(debug_size / 28) as usize {
            let record = debug + index * 28;
            if u32_at(self.bytes, record + 12)? != 2 {
                continue;
            }
            let cv = u32_at(self.bytes, record + 24)? as usize;
            if self.bytes.get(cv..cv + 4) != Some(b"RSDS") {
                continue;
            }
            let guid = self
                .bytes
                .get(cv + 4..cv + 20)
                .ok_or("truncated CodeView GUID")?
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let pdb_bytes = self.bytes.get(cv + 24..).ok_or("truncated PDB filename")?;
            let end = pdb_bytes
                .iter()
                .position(|b| *b == 0)
                .ok_or("unterminated PDB filename")?;
            let pdb_path = std::str::from_utf8(&pdb_bytes[..end]).map_err(|e| e.to_string())?;
            let pdb_file = pdb_path.rsplit(['/', '\\']).next().unwrap_or("").to_owned();
            return Ok(crate::symbols::SymbolRequest {
                module: path
                    .file_name()
                    .ok_or("PE has no filename")?
                    .to_string_lossy()
                    .into_owned(),
                name: name.to_owned(),
                path: path.to_string_lossy().into_owned(),
                base: 0,
                size: u32_at(self.bytes, self.optional + 56)?,
                machine: u16_at(self.bytes, self.nt + 4)?,
                timestamp: u32_at(self.bytes, self.nt + 8)?,
                checksum: u32_at(self.bytes, self.optional + 64)?,
                pdb_guid: guid,
                pdb_age: u32_at(self.bytes, cv + 20)?,
                pdb_file,
            });
        }
        Err("PE image has no RSDS PDB identity".to_owned())
    }
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or("truncated PE u16")?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("truncated PE u32")?
            .try_into()
            .unwrap(),
    ))
}
