use core::fmt;
use cursive::backends::curses::n::ncurses::OK;
use cursive::traits::*;
use cursive::views::{Button, Dialog, DummyView, EditView, LinearLayout, SelectView};
use cursive::Cursive;
use std::collections::BTreeMap;
use std::fmt::{write, Error};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{io::stderr, process::Command, result};

#[derive(Debug)]
struct WgInterface {
    private_key: String,
    public_key: String,
    listen_port: u16,
    fwmark: bool,
    peers: Vec<WgPeer>,
    show_priv: bool,
}

impl fmt::Display for WgInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let private_key = if self.show_priv {
            self.private_key.to_owned()
        } else {
            "(hidden)".to_string()
        };
        write!(f, "Private Key: {}\n", private_key)?;
        write!(f, "Public Key: {}\n", self.public_key)?;
        write!(f, "Listen Port: {}\n", self.listen_port)?;
        write!(f, "fwmark: {}\n", self.fwmark)?;
        write!(f, "----- Peers -----\n")?;
        for peer in self.peers.iter() {
            write!(f, "{}", peer)?;
        }
        write!(f, " ")
    }
}

#[derive(Debug)]
struct WgPeer {
    public_key: String,
    preshared_key: Option<String>,
    endpoint: String,
    allowed_ips: String,
    latest_handshake: u128,
    transfer_rx: u64,
    transfer_tx: u64,
    persistent_keepalive: bool,
}

impl fmt::Display for WgPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Public Key: {}\n", self.public_key)?;
        write!(
            f,
            "Preshared Key: {}\n",
            self.preshared_key
                .to_owned()
                .unwrap_or("(none)".to_string())
        )?;
        write!(f, "Endpoinr: {}\n", self.endpoint)?;
        write!(f, "Allowed Ips: {}\n", self.allowed_ips)?;
        write!(f, "Latest handshake: {}\n", self.latest_handshake)?;
        write!(
            f,
            "Transfer: {} B recieved, {} B sent\n",
            self.transfer_rx, self.transfer_tx
        )?;
        write!(f, "Persistent Keepalive: {}\n", self.public_key)
    }
}

fn main() {
    let mut siv = cursive::default();
    main_menu(&mut siv);
    siv.run();
}

fn refresh_interfaces() -> Result<BTreeMap<String, WgInterface>, Error> {
    let mut interfaces: BTreeMap<String, WgInterface> = BTreeMap::new();
    let result = Command::new("sudo")
        .arg("wg")
        .arg("show")
        .arg("all")
        .arg("dump")
        .output()
        .expect("Command failure");

    let raw_output = String::from_utf8_lossy(&result.stdout);
    let mut lines: Vec<&str> = raw_output.split("\n").collect::<Vec<&str>>();
    lines.pop();

    for (i, line) in lines.iter().enumerate() {
        let line: Vec<&str> = line.split("\t").collect();
        if line.len() == 5 {
            interfaces.insert(
                line[0].to_string(),
                WgInterface {
                    private_key: line[1].to_string(),
                    public_key: line[2].to_string(),
                    listen_port: line[3]
                        .parse()
                        .expect("Value {line[3]} could not be parsed to listen_port(u16)"),
                    fwmark: match line[4] {
                        "off" => false,
                        "on" => true,
                        _ => unreachable!(),
                    },
                    peers: lines
                        .iter()
                        .skip(i + 1)
                        .map(|x| x.split("\t").collect::<Vec<&str>>())
                        .take_while(|x| line[0] == x[0])
                        .map(|x| WgPeer {
                            public_key: x[1].to_string(),
                            preshared_key: match x[2] {
                                "(none)" => None,
                                _ => Some(x[2].to_string()),
                            },
                            endpoint: x[3].to_string(),
                            allowed_ips: x[4].to_string(),
                            latest_handshake: x[5].parse().expect(
                                "Value {x[5]} could not be parsed to latest_handshake(u64)",
                            ),
                            transfer_rx: x[6]
                                .parse()
                                .expect("Value {x[6]} could not be parsed to transfer_rx(u64)"),
                            transfer_tx: x[7]
                                .parse()
                                .expect("Value {x[7]} could not be parsed to transfer_tx(u64)"),
                            persistent_keepalive: match x[8] {
                                "off" => false,
                                "on" => true,
                                _ => unreachable!(),
                            },
                        })
                        .collect::<Vec<WgPeer>>(),
                    show_priv: false,
                },
            );
        }
    }
    Ok(interfaces)
}

fn main_menu(s: &mut Cursive) {
    s.pop_layer();
    let buttons = LinearLayout::vertical()
        .child(Button::new("list", list_connections))
        .child(Button::new("edit", Cursive::quit))
        .child(Button::new("Activate", Cursive::quit))
        .child(DummyView)
        .child(Button::new("Quit", Cursive::quit));

    s.add_layer(LinearLayout::horizontal().child(DummyView).child(buttons));
}

fn list_connections(s: &mut Cursive) {
    s.pop_layer();
    let interfaces = refresh_interfaces().unwrap();
    //let list: Vec<String> = interfaces.into_keys().collect();
    let view = SelectView::<String>::new()
        .with_all(interfaces.into_keys().map(|i| (format!("{}", i), i)))
        .on_submit(show_details);

    s.add_layer(view);
}

fn show_details(s: &mut Cursive, name: &str) {
    let interfaces = refresh_interfaces().unwrap();
    let interface = interfaces.get(name).unwrap();
    let textbox = Dialog::text(format!("{}", interface))
        .title(format!("{} info", name))
        .button("ok", pop);

    s.add_layer(textbox)
}

fn pop(s: &mut Cursive) {
    s.pop_layer();
}
