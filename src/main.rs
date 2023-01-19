/* wgtui - a terminal UI for wireguard
 *   Copyright (C) 2023 Iris Pupo
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use core::fmt;

use cursive::{
    traits::Nameable,
    views::{Button, Dialog, DummyView, LinearLayout, SelectView, TextView},
    Cursive,
};

use std::{
    collections::BTreeMap,
    fmt::{Debug, Error},
    process::{exit, Command},
    time::{SystemTime, UNIX_EPOCH}, fs,
};

use parking_lot::RwLock;

struct InterfacesMap {
    //TODO make sure that this can be mutated in the future
    interfaces: BTreeMap<String, WgInterface>,
}

impl InterfacesMap {
    pub fn new() -> InterfacesMap {
        let mut interfacesmap: InterfacesMap = InterfacesMap { 
                interfaces: BTreeMap::new(),
        };
        interfacesmap.refresh();
        interfacesmap
    }

    fn refresh(&mut self) {
        let mut interfaces: BTreeMap<String, WgInterface> = BTreeMap::new();
        let result = Command::new("wg")
            .arg("show")
            .arg("all")
            .arg("dump")
            .output()
            .expect("Command failure");
        //guarentee that user has proper permissions and that another error hasnt occured
        if !&result.status.success() {
            eprint!("{}", String::from_utf8_lossy(&result.stderr));
            exit(1);
        }

        let raw_output = String::from_utf8_lossy(&result.stdout);
        let mut lines: Vec<&str> = raw_output.split("\n").collect::<Vec<&str>>();
        //wireguard places a tab at the end which means that the last item the vector
        //is an empty string. We pop that last value to make sure we only have our
        //data in the string
        lines.pop();

        for (i, line) in lines.iter().enumerate() {
            let line: Vec<&str> = line.split("\t").collect();
            if line.len() == 5 {
                interfaces.insert(
                    line[0].to_string(),
                    WgInterface {
                        enabled: true,
                        private_key: line[1].to_string(),
                        public_key: line[2].to_string(),
                        listen_port: line[3]
                            .parse()
                            .expect("Value {line[3]} could not be parsed to listen_port(u16)"),
                        fwmark: match line[4] {
                            "off" => None,
                            _ => Some(line[4].to_string()),
                        },
                        //true fuckery. fill all the peers into their proper locations as long as the
                        //peer shares a name with the interface
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
        let interfaces_down = fs::read_dir("/etc/wireguard/")
            .unwrap()
            .map(|x| x.unwrap().file_name().into_string().unwrap())
            .filter(|x| x.contains(".conf"))
            .map(|x| x.replace(".conf", ""))
            .filter(|x| !interfaces.contains_key(x))
            .collect::<Vec<String>>();
        for item in interfaces_down {
            interfaces.insert(item, Default::default());
        }
        
        self.interfaces = interfaces;
    }
}

#[derive(Debug)]
struct WgInterface {
    enabled: bool,
    private_key: String,
    public_key: String,
    listen_port: u16,
    fwmark: Option<String>,
    peers: Vec<WgPeer>,
    show_priv: bool,
}

impl Default for WgInterface {
    fn default() -> Self {
        WgInterface {
            enabled: false,
            private_key: "".to_owned(),
            public_key: "".to_owned(),
            listen_port: 0,
            fwmark: None,
            peers: Vec::new(),
            show_priv: false,
        }
    }
}

impl fmt::Display for WgInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //guarentees that private key is only shown if the user has
        //decided to let it
        if !self.enabled {
            write!(f, "Interface is down.")
        }
        else{
            let private_key = if self.show_priv {
                self.private_key.to_owned()
            } else {
                "(hidden)".to_string()
            };
            write!(f, "Private Key: {}\n", private_key)?;
            write!(f, "Public Key: {}\n", self.public_key)?;
            write!(f, "Listen Port: {}\n", self.listen_port)?;
            write!(
                f,
                "fwmark: {}\n",
                self.fwmark.to_owned().unwrap_or("off".to_string())
            )?;
            write!(f, "----- Peers -----\n")?;

            //display all the peers in the vector
            for peer in self.peers.iter() {
                write!(f, "{}", peer)?;
                //seperate multiple peers
                write!(f, "\n")?;
            }
            write!(f, " ")
        }
    }
}

#[derive(Debug)]
struct WgPeer {
    public_key: String,
    preshared_key: Option<String>,
    endpoint: String,
    allowed_ips: String,
    latest_handshake: u64,
    transfer_rx: u64,
    transfer_tx: u64,
    persistent_keepalive: bool,
}

impl fmt::Display for WgPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        //get current time in seconds
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time_since = time - self.latest_handshake;

        //returns a formatted string given the time.
        let time_since = time_to_english(time_since)?;

        write!(f, "Public Key: {}\n", self.public_key)?;
        write!(
            f,
            "Preshared Key: {}\n",
            self.preshared_key
                .to_owned()
                .unwrap_or("(none)".to_string())
        )?;
        write!(f, "Endpoint: {}\n", self.endpoint)?;
        write!(f, "Allowed Ips: {}\n", self.allowed_ips)?;
        write!(f, "Latest handshake: {}\n", time_since)?;
        write!(
            f,
            "Transfer: {} B recieved, {} B sent\n",
            self.transfer_rx, self.transfer_tx
        )?;
        write!(f, "Persistent Keepalive: {}\n", self.persistent_keepalive)
    }
}

static INTERFACES: RwLock<InterfacesMap> = RwLock::new(InterfacesMap{
    interfaces: BTreeMap::new(),
});

fn time_to_english(mut time: u64) -> Result<String, fmt::Error> {
    let mut output = "".to_string();
    let mut days = 0;
    let mut hours = 0;
    let mut minutes = 0;

    //count the days hours and minutes. What remains will be seconds
    while time >= 60 {
        if time >= 86400 {
            time -= 86400;
            days += 1;
        } else if time >= 3600 {
            time -= 3600;
            hours += 1;
        } else if time >= 60 {
            time -= 60;
            minutes += 1;
        }
    }

    if days > 0 {
        output += &days.to_string();
        output += if days == 1 { " day " } else { " days " };
    }
    if hours > 0 {
        output += &hours.to_string();
        output += if hours == 1 { " hour " } else { " hours " };
    }
    if minutes > 0 {
        output += &minutes.to_string();
        output += if minutes == 1 {
            " minute "
        } else {
            " minutes "
        };
    }
    if time > 0 {
        output += &time.to_string();
        output += if time == 1 { " second" } else { " seconds" };
    }
    Ok(output)
}

fn main() {
    let mut siv = cursive::default();
    main_menu(&mut siv);
    INTERFACES.write().refresh();
    siv.run();
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
    let details = TextView::new("").with_name("details");
    let interface_list = SelectView::<String>::new()
        //map all interface keys(names) into my SelectView
        .with_all_str(INTERFACES.read().interfaces.keys())
        .on_select(|s, item| {
            let content = format!("{}", INTERFACES.read().interfaces.get(item).unwrap());
            s.call_on_name("details", |v: &mut TextView| {
                v.set_content(content);
            })
            .unwrap();
        })
        .on_submit(show_details);

    s.add_layer(
        Dialog::around(
            LinearLayout::horizontal()
                .child(interface_list)
                .child(DummyView)
                .child(details),
        )
        .title("Interfaces"),
    );
}

fn show_details(s: &mut Cursive, name: &str) {
    let piss = INTERFACES.read();
    let interface = piss.interfaces.get(name).unwrap();
    let textbox = Dialog::text(format!("{}", interface))
        .title(format!("{} info", name))
        .button("ok", pop);

    s.add_layer(textbox);
}

//TODO get rid of this
fn pop(s: &mut Cursive) {
    s.pop_layer();
}
