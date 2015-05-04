extern crate libc;
extern crate regex;

//extern crate native;
use libc::{c_int, c_void, socket, AF_INET, AF_PACKET, sockaddr_storage};
use std::io::{Read, Seek};
use std::path::Path;
use std::thread;
use std::fs::File;
use std::mem;
use std::io::{BufReader, Bytes, BufRead};
use std::collections::HashMap;
use std::process::Command;
use regex::Regex;

mod packet;

static SOCK_RAW: c_int = 3;
static ETH_P_IP:  u16 = 0x0800;
static ETH_P_ALL: u16 = 0x0003;

#[derive(Debug, Clone, Copy)]
enum IPProtoType {
    IP   = 0,
    ICMP = 1,
    IGMP = 2,
    TCP  = 6,
    UDP  = 17,
    RAW  = 255,
}

#[derive(Debug)]
struct RawSocket {
    fd: c_int,
    proto: IPProtoType
}

impl RawSocket {
    fn new(proto: IPProtoType) -> Result<RawSocket, &'static str> {
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW, ETH_P_IP.to_be() as i32) };
        if fd >= 0 {
            Ok(RawSocket { fd: fd, proto: proto })
        } else {
            Err("Fail to create raw socket, run as root?")
        }
    }

    fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<usize, &'static str> {
        let bytes = unsafe { libc::recv(self.fd,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u64, 
            0) };
        if bytes > 0 {
            Ok(bytes as usize)
        } else {
            Err("fail to recvfrom")
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd); }
        println!("socket {} closed", self.fd);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RouteItem {
    net: u32,
    mask: u32,
}

impl RouteItem {
    fn int2mask(k: u32) -> u32{
        assert!(k <= 32);
        let mut m = 0;
        for i in 0..k {
            m |= 1 << (31 - i)
        }
        m
    }

    fn parse(s: &str) -> RouteItem {
        let m: Vec<_> = s.split('/').collect();
        let a: Vec<u32> = m[0].split('.').map(|e| e.parse::<u32>().unwrap()).collect();
        let ip = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
        let mask = RouteItem::int2mask(m[1].parse::<u32>().unwrap());
        RouteItem {
            net: ip & mask,
            mask: mask
        }
    }

    fn net2addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(
            (self.net >> 24) as u8,
            (self.net >> 16) as u8,
            (self.net >> 8) as u8,
            (self.net) as u8
        )
    }
}

#[derive(Debug)]
struct RouteTable {
    items: Vec<RouteItem>,
}

impl RouteTable {
    fn new(file: &str) -> RouteTable {
        let path = Path::new(file);
        let mut file = BufReader::new(File::open(&path).unwrap());
        let mut items: Vec<RouteItem> = Vec::new();
        for line in file.lines().filter_map(|result| result.ok()) {
            items.push(RouteItem::parse(&line));
        }
        println!("read {} items", items.len());
        items.sort();
        RouteTable {
            items: items
        }
    }

    fn find(&self, ip: &std::net::Ipv4Addr) -> Option<&RouteItem> {
        let o = ip.octets();
        let k = ((o[0] as u32) << 24) 
            | ((o[1] as u32) << 16)
            | ((o[2] as u32) << 8)
            | (o[3] as u32);
        let m = RouteItem { net: k, mask: 0xffffffff };
        let t = self.items.binary_search_by(|p| p.cmp(&m));
        match t {
            Ok(i) => Some(&self.items[i]),
            Err(i) => {
                if i == 0 {
                    None
                } else {
                    let idx = i - 1;  // lower bound
                    if self.items[idx].net == k & self.items[idx].mask {
                        Some(&self.items[idx])
                    } else {
                        None
                    }
                }
            }
        }
    }
}

struct Router {
    ip_cache: HashMap<std::net::Ipv4Addr, usize>,
    route_table: RouteTable,
}

impl Router {
    fn new() -> Router {
        Router {
            ip_cache: HashMap::new(),
            route_table: RouteTable::new("cn.zone")
        }
    }

    fn is_private(ip: &std::net::Ipv4Addr) -> bool {
        match (ip.octets()[0], ip.octets()[1]) {
            (10, _) => true,
            (172, b) if b >= 16 && b <= 31 => true,
            (192, 168) => true,
            (127, _) => true,
            _ => false
        }
    }

    fn do_packet(&mut self, h: packet::Ipv4Header) {
        // XXX
        if Router::is_private(&h.src_ip) {
            return;
        }
        let ip = h.src_ip.clone();
        if self.ip_cache.len() > 10000 {
            // XXX use LRU, do sweep
        }
        let old = self.ip_cache.insert(ip, 0);
        match old {
            None => {
                match self.route_table.find(&ip) {
                    Some(r) => return,
                    None => {
                        // NOT in white list
                        thread::spawn(move || {
                            let re_pl = Regex::new(r"(\d+)% packet loss, time (\d+)ms").unwrap();
                            //println!("Testing {}", h.src_ip);
                            let cmd = format!("ip netns exec direct ping -q -W 2 -c 10 -i 0.2 {}", h.src_ip);
                            let output = Command::new("/bin/sh")
                            .arg("-c").arg(cmd)
                            .output().unwrap_or_else(|e| {
                                panic!("failed to execute process: {}", e)
                            });
                            let s = String::from_utf8_lossy(&output.stdout);
                            let lines = s.split("\n").filter(|e| e.len() > 0);
                            let mut loss = 0;
                            let mut time = 0;
                            let mut valid = false;
                            for l in lines {
                                match re_pl.captures(l) {
                                    None => continue,
                                    Some(c) => {
                                        //println!("XXXXX {}", c.at(0).unwrap());
                                        loss = c.at(1).unwrap().parse::<u32>().unwrap();
                                        time = c.at(2).unwrap().parse::<u32>().unwrap();
                                        valid = true;
                                    }
                                }
                            }
                            if valid {
                                println!("IP: {}, count: 10, loss: {}, time: {}", h.src_ip, loss, time);
                            }
                            // println!("output: {}", s);
                        });
                        return
                    }
                }
            },
            Some(v) => return
        }
    }
}


fn main() {
    let mut raw = RawSocket::new(IPProtoType::TCP).unwrap();
    let mut buf = [0u8; 65535];
    let mut router = Router::new();
    println!("starting main loop...");
    loop {
        match raw.recv(&mut buf) {
            Ok(size) => {
                let buf = &buf[0..size];
                let p = packet::Ipv4Header::parse(buf);
                match p {
                    Some(h) => {
                        router.do_packet(h);
                    },
                    None => continue
                }
            }
            Err(_) => continue
        }
    }
}
