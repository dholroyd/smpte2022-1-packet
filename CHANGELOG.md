# Change Log

## 0.4.0
### Changed 
 - Made `FecHeader::sn_base_low_bits()` public, since that's the one everyone will need.

## 0.3.0

### Changed
 - `sn_base_low_bits()` now returns a `rtp_rs::Seq`, rather than a `u16` (and crate `rtp-rs` is added as a dependency
   to provide this type).

### Added
 - `associates_with()` function to test if the packet with the given RTP sequence number is protected by this FEC
   packet.