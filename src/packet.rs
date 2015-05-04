use std::net::Ipv4Addr;
//use std::io::net::ip::Ipv4Addr;

// fn chksumbytes(byts: &[u8]) -> u16 {
//     let mut checksum: u32 = 0;
//     let len = byts.len();
//     let padd = (len % 2);
// 
//     for i in range_step_inclusive(0, len-1-padd, 2) {
//         let snip = ((byts[i] as u16) << 8) | (byts[i+1] as u16);
//         checksum += snip as u32;
//     }
//     if padd != 0 {
//         checksum += (byts[len-1] as u32) << 8;
//     }
//     loop {
//         let y = checksum >> 16;
//         if y == 0 { break; }
// 
//         checksum = (checksum & 0xffff) + y
//     }
//     checksum = !checksum;
//     return checksum as u16;
// }

#[derive(Clone, Copy)]
pub enum Ethertype {
    Ethertype_IP = 0x0800,
    Ethertype_ARP = 0x0806,
    Ethertype_VLAN = 0x8100,
    Ethertype_Unknown = 0x0000,
}

pub struct EthernetHeader {
    dst_mac:    [u8; 6],
    src_mac:    [u8; 6],
    ethertype:  Ethertype,
}

impl EthernetHeader {
    pub fn len(&self) -> usize { 14 }
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut res = Vec::new();
        res.extend(self.dst_mac.iter().cloned());
        res.extend(self.src_mac.iter().cloned());
        res.push( (self.ethertype as u16 >> 8) as u8  );
        res.push( self.ethertype as u8 );
        res
    }
}

#[derive(Debug)]
pub struct Ipv4Header {
    pub version:       u8,
    pub ihl:           u8,
    pub diff_services: u8,
    pub ecn:           u8,
    pub total_len:     u16,
    pub id:            u16,
    pub flags:         u8,
    pub frag_offset:   u16,
    pub ttl:           u8,
    pub protocol:      u8,
    pub checksum:      u16,
    pub src_ip:        Ipv4Addr,
    pub dst_ip:        Ipv4Addr,
}

impl Ipv4Header {
    pub fn parse(h: &[u8]) -> Option<Ipv4Header> {
        if h.len() < 20 {
            return None;
        }
        if h[0] != 0x45 {
            return None;
        }
        let ihl = h[0] & 0b00001111;
        Some(Ipv4Header{
            version: 0x04,
            ihl:            ihl,
            diff_services:  h[1] >> 2,
            ecn:            h[1] & 0b00000011,
            total_len:      (h[2] as u16) << 8 | (h[3] as u16),
            id:             (h[4] as u16) << 8 | (h[5] as u16),
            flags:          (h[6] >> 5) & 0b00000111,
            frag_offset:    ((h[6] as u16) << 8 | h[7] as u16) & 0b0001111111111111,
            ttl:            h[8],
            protocol:       h[9],
            checksum:       ((h[10] as u16) << 8) | (h[11] as u16),
            src_ip:         Ipv4Addr::new(h[12], h[13], h[14], h[15]),
            dst_ip:         Ipv4Addr::new(h[16], h[17], h[18], h[19]),
        })
    }
}
