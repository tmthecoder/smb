macro_rules! impl_smb_from_bytes {
    ($num_type: ty, $input: expr, $size: expr) => {{
        if $input.len() < $size {
            return Err(SMBError::ParseError("Byte slice too small".into()));
        }
        let flags = Self::from_bits_truncate(<$num_type>::from_le_bytes(<[u8; $size]>::try_from(&$input[0..$size])
            .map_err(|_e| SMBError::ParseError("Invalid byte slice".into()))?));
        Ok((&$input[$size..], flags))
    }}
}

pub(crate) use impl_smb_from_bytes;