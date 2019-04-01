//! Zero-copy access to the header fields of packets formatted according to
//! [SMPTE 2022-1](https://en.wikipedia.org/wiki/SMPTE_2022), also know as 'Pro MPEG FEC' or '1D/2D
//! parity FEC'.
//!
//! Note this does **not implement FEC encoding or decoding**, just the parsing of the packet
//! header fields.  For a decoder, see the
//! [smpte2022-1-fec crate](https://crates.io/crates/smpte2022-1-fec).
//!
//! ## Header data format
//!
//! ```plain
//! syntax fec_header() {
//!     SNBase low bits             u16
//!     Length Recovery             u16
//!     E                           u1
//!     PT recovery                 u7
//!     Mask                        u24
//!     TS recovery                 u32
//!     N                           u1
//!     D                           u1
//!     type                        u3
//!     index                       u3
//!     Offset                      u8
//!     NA                          u8
//!     SNBase ext bits             u8
//! }
//! ```

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, future_incompatible, missing_docs)]

use std::fmt;

/// Identifies whether a FEC packet belongs to the is associated with a 'row' or a 'column' of
/// media packets.
#[derive(Debug, PartialEq)]
pub enum Orientation {
    /// FEC packet protects a row (indicated by the `D` field in the spec having value `1`).
    Row,
    /// FEC packet protects a column (indicated by the `D` field in the spec having value `0`).
    Column,
}

/// Errors which may occur when trying to parse FEC header data
#[derive(Debug)]
pub enum FecHeaderError {
    /// The given buffer is too short to contain FEC headers (16 bytes, for SMPTE 2022-1)
    BufferTooShort(usize),
    /// The `e` (extended) flag is set to `0` (SMPTE 2022-1 requires that it is set to `1`).
    ExtendedFlagNotSet,
    /// the `offset` field unexpectedly had the value `0`
    OffsetValueZero,
    /// the `NA` field unexpectedly had the value `0`
    NumberAssociatedValueZero,
}

/// The set of headers values in a SMPTE 2022-1 packet.
pub struct FecHeader<'buf> {
    buf: &'buf [u8],
}
impl<'buf> FecHeader<'buf> {
    const MIN_HEADER_LEN: usize = 12;

    /// wrap the given byte-slice in a `FecHeader` object, or return a FecHeaderError if the given
    /// slice does not represent a valid header.
    pub fn from_bytes(buf: &'buf [u8]) -> Result<FecHeader<'buf>, FecHeaderError> {
        if buf.len() < Self::MIN_HEADER_LEN {
            return Err(FecHeaderError::BufferTooShort(buf.len()));
        }
        let res = FecHeader { buf };
        if !res.extended() {
            return Err(FecHeaderError::ExtendedFlagNotSet);
        }
        if res.offset() == 0 {
            return Err(FecHeaderError::OffsetValueZero);
        }
        if res.number_associated() == 0 {
            return Err(FecHeaderError::NumberAssociatedValueZero);
        }
        if buf.len() < res.header_len() {
            return Err(FecHeaderError::BufferTooShort(buf.len()));
        }
        Ok(res)
    }

    /// Returns a `FecHeader`, and the remaining payload data from the given slice immediately
    /// following the header.
    pub fn split_from_bytes(
        buf: &'buf [u8],
    ) -> Result<(FecHeader<'buf>, &'buf [u8]), FecHeaderError> {
        let len = Self::from_bytes(buf)?.header_len();
        let (buf, tail) = buf.split_at(len);
        Ok((FecHeader { buf }, tail))
    }

    /// Returns the length in bytes of the headers this object represents.
    pub fn header_len(&self) -> usize {
        if self.extended() {
            Self::MIN_HEADER_LEN + 4
        } else {
            Self::MIN_HEADER_LEN
        }
    }

    /// 24 bit value of the minimum sequence number of media packets associated with this FEC packet
    pub fn sn_base(&self) -> u32 {
        u32::from(self.sn_base_ext_bits()) << 16 | u32::from(u16::from(self.sn_base_low_bits()))
    }

    /// The low 16 bits of the minimum sequence number of media packets associated with this FEC packet
    pub fn sn_base_low_bits(&self) -> rtp_rs::Seq {
        rtp_rs::Seq::from(u16::from(self.buf[0]) << 8 | u16::from(self.buf[1]))
    }
    /// The length of media packets associated with this FEC packet
    pub fn length_recovery(&self) -> u16 {
        u16::from(self.buf[2]) << 8 | u16::from(self.buf[3])
    }

    /// Flag indicating if this header includes extension fields (must be `true` for SMPTE 2022-1
    /// packets
    pub fn extended(&self) -> bool {
        self.buf[4] & 0b1000_0000 != 0
    }

    /// Field allowing recovery of the _payload type_ of media packets associated with this FEC
    /// packet
    pub fn pt_recovery(&self) -> u8 {
        self.buf[4] & 0b0111_1111
    }

    /// Set to all-zeros for SMPTE 2022-1 streams
    pub fn mask(&self) -> u32 {
        u32::from(self.buf[5]) << 16 | u32::from(self.buf[6]) << 8 | u32::from(self.buf[7])
    }

    /// Used to recover the _timestamp_ field of any packets associated with this FEC packet
    pub fn ts_recovery(&self) -> u32 {
        u32::from(self.buf[8]) << 24
            | u32::from(self.buf[9]) << 16
            | u32::from(self.buf[10]) << 8
            | u32::from(self.buf[11])
    }

    /// `Orientation::Column` for FEC packets from the first FEC stream, and `Orientation::Row` for
    /// FEC packets from the second FEC stream.
    ///
    /// In the spec this header field is named `D`.
    pub fn orientation(&self) -> Orientation {
        if self.buf[12] & 0b0100_0000 != 0 {
            Orientation::Row
        } else {
            Orientation::Column
        }
    }

    /// 3-bit value indicating which error-correcting code is chosen, but always set to `0` for
    /// SMPTE 2022-1 streams.
    ///
    /// Packets with an unrecognized value to be ignored.
    pub fn fec_type(&self) -> u8 {
        (self.buf[12] >> 3) & 0b111
    }

    /// 3-bit value always set to `0` for SMPTE 2022-1 streams.
    pub fn index(&self) -> u8 {
        self.buf[12] & 0b111
    }

    /// Selects the media packets associated with this FEC packet.
    ///
    /// Equal to the the `L` parameter for the first FEC stream, and always equal to `1` for
    /// the second FEC stream.
    pub fn offset(&self) -> u8 {
        self.buf[13]
    }

    /// The number of media packets associated with this FEC packet.
    ///
    /// This is the `NA` field from the spec, equal to the `D` parameter or FEC packets belonging
    /// to the first FEC stream, and equal to the `L` parameter or FEC packets belonging
    /// to the second FEC stream.
    pub fn number_associated(&self) -> u8 {
        self.buf[14]
    }
    /// The top 8 bits of the sequence number, or `0` if the sequence number fits in the 16 bits
    /// `sn_base` field.
    pub fn sn_base_ext_bits(&self) -> u8 {
        self.buf[15]
    }

    /// `true` iff a packet with the given sequence number would be associated with this FEC packet
    pub fn associates_with(&self, seq: rtp_rs::Seq) -> bool {
        let base = self.sn_base_low_bits();
        let na = u16::from(self.number_associated());
        let off = u16::from(self.offset());
        let end = base + na * off;
        base <= seq && seq < end && self.same_column(seq)
    }

    /// `true` if the packet with the given sequence number is in the same column as this packet,
    /// or if this packet is anyway a row packet (i.e. it's 'offset' is `1`)
    fn same_column(&self, seq: rtp_rs::Seq) -> bool {
        let off = u16::from(self.offset());
        u16::from(seq) % off == u16::from(self.sn_base_low_bits()) % off
    }
}

impl<'buf> fmt::Debug for FecHeader<'buf> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("FecHeader")
            .field("sn_base", &self.sn_base())
            .field("length_recovery", &self.length_recovery())
            .field("pt_recovery", &self.pt_recovery())
            .field("mask", &self.mask())
            .field("ts_recovery", &self.ts_recovery())
            .field("orientation", &self.orientation())
            .field("fec_type", &self.fec_type())
            .field("index", &self.index())
            .field("offset", &self.offset())
            .field("number_associated", &self.number_associated())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::*;

    #[test]
    fn column() {
        let data = hex!("6ce40524a10000000a91778f00140500471fff16dc0d01fe70bc61a31668cbbaf9c45ec52e4ce3c8c977c99d7fad0459b40e647f07b7e3fa7140027ea859ebddc28a1c20f94ed52d171e4cecfda81bb56eb9cb73d928f4b95b82399cae25998bd362c699bac4603b80a354f927b95af806fe003c0cf132cda74495456915bdbe27bcc40aa98c111db2403de503a2eeeda394a738c61edfc60843889a9dbc9fc72848bc93e0b91589c89794224b0a45e94332a47f2dcd4f1dd849e0a9e92be2d3be4800e530582b3fc93d52d3471fff1c78c25d67fdfd7fc99d0e68fdff60aa788ed0d0c721364c3eb198e3caaaabf142a0e6b240839ea7ea06a823924ade4438a8e7d4429d1278cc943e5f70b15c59ab7b2b7dcee63c36deba80c558f08ecb508d4488fb775794930c114fcdf6332c789a113acaf79f12a5e94d474cd0acd9b1ae453c46d334ffb82f175484c0bc62f600e49dd6fff2efe4e4013d6848f62e669b0cbba79261cf88817845eb0f3d58f5149da55e4245ef8d32b3147496a95cc13f06dd499c13cd7f4701001c1825b0a939929cefa60c38fa416482be5c258a2dadff49be137ec1c406118011c77d724dc16c01388dfbea00a5cefd9a9e5fe59c1e65e37d51f6d412f91be5fe3f71b32b34dd0fe987eeb05d00c8bd97cc25d062be8f68c93533c3dcb71bc2b056d1eea5b39a538bfad2574c723aebc7af50f5e210068200ff889448096dbc6e30b20d728be3770ca83dad60aefdbc7b5186cda2e6265d70caca955ba02fafd38d0f9b4861f17a9e04bef75b93a0d16e955e9b01711957f2470100114c63855ef93f0487c61677779ff4e873f676eecbf2ec59ee9c4c38c4b1a8b2f4f9cf43723b5eb1f441da8fa6733598ef7a0ce568ebe70cca2c4e73ee4d9c318e30ae0a0d7b599902f3708ce1b421a75c5235beb2681d8f3a5e065443be9cfffe5ba96c2183830d623dd3028f69558c7a51c9ac994ade44276215f2b9b5d08bfaa0c50d3b467490e3e76174367c5aa18d928926f2cf740a88f7bff14afa78c05c7f716075a2c29e483aa3ad02f5419cfbd6d993e7c5814d5e47010233c09e40ae80fe003c4050a9abc4ad38a113f5e5173051388c28a2c34548f656f1abb68fc3de43d4e754e006785021f4c86958b586e97aae7ddf0359725318a708abd79d07ad0283a667f64a6668915c7d3981565a24c24083d3284671224e0654db4797b72fbb9f79ab7d48c7a108f9ef3ba96f25a50e1613e9ef314094856c8aa11cdc578e1433af23fc4d9a75ab6708941be898e1c87647d0e56fc8142a2c45709a91b1a81379ed3c4664c508c80a67bb644ad6d926e2574701011b8f97bb48cf034d5f110eea7354cea308276441edd4f19af0029395d5a1d19ce68c275e225bf2e88dbaebd2cd6b7ad9b13a63a98fadaf78d6dfa7f6badfbb4178528ced7c0aebee87419c531947181daf694563803f09ca40b98c49e3a8e136ac95c66f07e5df066964a8551a5c7f03f49e0cdb0ce0bf2a6579d3d449db7981efedb1a892b4e4e8df7d9cb6bbc6bc2e23c09f48f1e8ab6a685c0db0fed18f9633eec3c207c360f6c9757ad170b8f9a6dc583bab326bcc5d78471fff10a8dc109c615262eab0a426c635732e4f13e0d4c9575e41521d91660ac5f80001836e342cd7aeca98c167acda39c6b5a684d427b5700af75b926d7f78768cf9bca8807249967f068fe2d7060f435a6bc0c4162f7da34dc37d0c9d52c51f89562b84e64580b727fb684ce4ad560cfa364d9df02f4c2efd70b4ba074112a0634e82ba904a570e84a5700927696262955d70a1694c46ad18f787098586c811ce4d4205533724207624c109fb04eabfa033d1e07cc1423bcd322a");
        let (header, payload) = FecHeader::split_from_bytes(&data[..]).unwrap();
        assert_eq!(header.header_len(), 16);
        assert_eq!(header.sn_base(), 27876);
        assert_eq!(header.length_recovery(), 0x00000524);
        assert_eq!(header.mask(), 0);
        assert_eq!(header.ts_recovery(), 0x0a91778f);
        assert_eq!(header.orientation(), Orientation::Column);
        assert_eq!(header.fec_type(), 0);
        assert_eq!(header.index(), 0);
        assert_eq!(header.offset(), 20);
        assert_eq!(header.number_associated(), 5);
        assert!(payload.starts_with(&hex!("471fff16dc0d")[..]));
        dbg!(header);
    }

    #[test]
    fn row() {
        let data = hex!("7e6100008000000000000d6640011400001efe0b97249db8582ac143b90e9b3975a18c703817a6b1ef1035dc70edc70b67e407f57b0db156065f95baabaeeaab82d3b6a869b117c327c8f91e3b521c78a63e24bafe955d907258815b273fcc14a7d05ad3844139bb41bab400654e3e94fa3609234532e126c18a525154f0fcc52347e2c1a842d667de613fc0c79b475daffd50e0a4270df99310ed69ef211a1f2c7cdb0cda7dace687a34fb125ca480f3636764c01c42ed3bacb2e8d5eecbf11332056d0e670f380d77abbb3001eff0e5e42da393c535a3025e40cab385fd1059cc67337f9871b8823742999391d72404e65db85426ecfd34ea30e8d4850440903a7fe4c6dc0f6494153e08e2d880cd54d8f5e76afeaaee17257af357fe28404f788851369dc93b384c437620664692a9a835d2a54b191d18354e433b5955e41a15621acf0ee0b8813c8db09e4148f6c8069c4618319169c663f5d7907c15855c491c340f6ce1708e7afb99d778fd18714caba17411734f69069134964aa7210041a4a7f9619dac8001efd2740d92f5846c3222be733cdb938489ca0d0a927e4f8dbbc116da9999581b9fc757427c2d6aa7c967f10972e147b51928cd9b375c12eaac8c43740ee8e3b9da85183a9b61e23e969f6e00fac6e92d5c821c4a29cf0500608c6b539c96266c188b9f2b1f3a04f827b763a75cf6b5c659b63afcb58000b330b12325a1df557c0f636d3c2504b46327713da56f68ea5e233c634a3f566800b0d38f2ff9b5a1ba0712f45f43209a4742608fc68ede9c33ff6a37b1531c07dd66cc8005efd0de4fdea3f01961dbb0d5f138a06d241c582942ef929fd59bb0dfb4d0a15c04c0c4a2623056a7ba8000663f314fc9bc4a60c46fb314d665e074aa6124bde35d23393f951e1ebf02429f5ccce4da6b312fb31840b11f54d825f77504dcd4d4a0fbfa343c110baa3dda2f5ca1e0a3d31fda1edda34d946009c78a86780f8be8c9cb4423a6d2c452cbd9c9ddaf567836c2154cdbe7f781a4a5e6e042d8715a514962c38436885bfd632b728c8404ea2b56ecf2f095d4d98b84ee50000012e0739f29e76c8c6efd1603ebe9aa00179624fe383a56b562fb893d4ec9bad6eae1d0206ba6557543530e109a866afbaf50c9671ccb3daaf0f62fe44ae30ee33fc72dac60bd3f9f7c2d6638ebba1a8a1528acff6f278902caa09060e84a3fb64cd403de93318d0a8724b1bb266ebf6fc456b2f643b8a81f7b898599485349c40eae783217f030a37c7f01c100260932514c8060fe41437364d1aedf8b554077df6de7f8d147040ead501d28e613273b51b1e632932b92b5a860000000ac26f8e44befa5b6b1b1cd5a60da71a8a534fa3f34fb580c9634d3609493318efb796df9b61ae1437363dc74e01896c7eca291d9d1cac3db85a57c041924f55ff74e756570000000c4941f7a9ce78b76e8a7b6a400a26b96c482bdd077f4f1f4433e3ca4faee62317f2a0b663d6be0f8cbce3e292470382d738d50a07de61188b217f4d57b6ea7b830f7154bfd60e3a74c0f2030b1873afa27ceffa597744a583831a563852647cf1051b8967d6e6f41d552637512c69fd0b001eff0f7f663d7cf5a87ab377056df8517b89a45abee3553a8ff4c3c448ddff1e4cb32d401d5ee2b95e3615f050e7e4eeda4e76ca667840e3acb10a9b627a4b251fa28d23c7c40dc486c50e878914ea844ccc55069d948543dd01d5640db169090fd5ea411dfa796f818438b93ae53f2f3e7b15413868044fd717d4c4c8356023d470898d5d72ae72ba2a8887f8af4ab4dd5167126f47d98b91284108e64e886073ad31173abd2f06f762e29a2bd8ce34a323e7cc9027c7faeecd9d");
        let (header, payload) = FecHeader::split_from_bytes(&data[..]).unwrap();
        assert_eq!(header.header_len(), 16);
        assert_eq!(header.sn_base(), 32353);
        assert_eq!(header.mask(), 0);
        assert_eq!(header.ts_recovery(), 0x00000d66);
        assert_eq!(header.orientation(), Orientation::Row);
        assert_eq!(header.fec_type(), 0);
        assert_eq!(header.index(), 0);
        assert_eq!(header.offset(), 1);
        assert_eq!(header.number_associated(), 20);
        assert!(payload.starts_with(&hex!("001efe0b9724")[..]));
        dbg!(header);
    }
}
