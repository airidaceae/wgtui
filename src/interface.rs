use core::fmt;
use std::{
    collections::BTreeMap,
    fmt::{format, Debug, Error},
    fs,
    process::{exit, Child, Command},
    time::{SystemTime, UNIX_EPOCH},
};



pub struct InterfacesMap {
    pub interfaces: BTreeMap<String, WgInterface>,
    pub current_interface: String,
}

impl InterfacesMap {
    pub const fn new() -> InterfacesMap {
        let interfacesmap: InterfacesMap = InterfacesMap {
            interfaces: BTreeMap::new(),
            current_interface: String::new(),
        };
        interfacesmap
    }

    pub fn refresh(&mut self) {
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
                        show_priv: false,
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
pub struct WgInterface {
    pub enabled: bool,
    pub private_key: String,
    pub public_key: String,
    pub listen_port: u16,
    pub fwmark: Option<String>,
    pub peers: Vec<WgPeer>,
    pub show_priv: bool,
}
impl WgInterface {
    pub fn toggle_privkey(&mut self){
        self.show_priv = !self.show_priv;
    }
}
impl Default for WgInterface {
    fn default() -> Self {
        WgInterface {
            enabled: false,
            private_key: String::new(),
            public_key: String::new(),
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
        } else {
            let private_key = if self.show_priv {
                self.private_key.to_owned()
            } else {
                String::from("(hidden)")
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
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: String,
    pub allowed_ips: String,
    pub latest_handshake: u64,
    pub transfer_rx: u64,
    pub transfer_tx: u64,
    pub persistent_keepalive: bool,
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
                .unwrap_or(String::from("(none)"))
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

//TODO: improve this
fn time_to_english(mut time: u64) -> Result<String, fmt::Error> {
    let mut output = String::new();
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

