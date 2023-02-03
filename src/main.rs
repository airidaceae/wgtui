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

mod interface;

use crate::interface::*;
use cursive::{
    Cursive,
    traits::Nameable,
    views::{Button, Dialog, DummyView, LinearLayout, SelectView, TextView},
};
use parking_lot::RwLock;
use std::process::Command;

static INTERFACES: RwLock<InterfacesMap> = RwLock::new(InterfacesMap::new());

fn main() {
    let mut siv = cursive::default();
    main_menu(&mut siv);
    INTERFACES.write().refresh();
    siv.run();
}

fn main_menu(s: &mut Cursive) {
    s.pop_layer();
    s.add_global_callback('q', |s| s.quit());
    s.add_global_callback('q', |s| s.quit());
    let buttons = LinearLayout::vertical()
        .child(Button::new("list", list_connections))
        .child(Button::new("edit", Cursive::quit))
        .child(Button::new("Activate", Cursive::quit))
        .child(DummyView)
        .child(Button::new("Quit", Cursive::quit));
    s.add_layer(
        Dialog::around(LinearLayout::horizontal().child(DummyView).child(buttons)).title("WGTUI"),
    );
}

fn list_connections(s: &mut Cursive) {
    s.pop_layer();
    INTERFACES.write().refresh();
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
        .on_submit(interface_select);
    let buttons = LinearLayout::horizontal()
        .child(Button::new("Toggle Private Keys", swap_priv))
        .child(DummyView)
        .child(Button::new("Refresh", refresh_list))
        .child(DummyView)
        .child(DummyView)
        .child(Button::new("Back", ret2main));

    s.add_layer(
        Dialog::around(
            LinearLayout::vertical()
                .child(
                    LinearLayout::horizontal()
                        .child(interface_list)
                        .child(DummyView)
                        .child(details),
                )
                .child(DummyView)
                .child(buttons),
        )
        .title("Interfaces"),
    );
}

fn refresh_list(s: &mut Cursive) {
    s.pop_layer();
    list_connections(s);
}

fn ret2main(s: &mut Cursive) {
    s.pop_layer();
    main_menu(s);
}

fn swap_priv(s: &mut Cursive) {
    s.pop_layer();
    let inverted = !INTERFACES.read().show_priv;
    INTERFACES.write().show_priv = inverted;
    //leaving this commented here bc im proud of it
    //INTERFACES.write().interfaces.iter_mut().for_each(|(_, v)| v.show_priv = !v.show_priv);
    list_connections(s);
}

fn interface_select(s: &mut Cursive, name: &str) {
    s.pop_layer();
    INTERFACES.write().current_interface = name.to_string();
    let buffer = INTERFACES.read();
    let interface = buffer.interfaces.get(name).unwrap();
    let textbox = Dialog::text(format!("{}", interface))
        .title(format!("{}", name))
        .button("ok", list_connections)
        .button(
            if interface.enabled {
                "disable"
            } else {
                "enable"
            },
            |s| change_state(s),
        );

    s.add_layer(textbox);
}

fn change_state(s: &mut Cursive) {
    let name = &INTERFACES.read().current_interface;
    let enabled = INTERFACES.read().interfaces.get(name).unwrap().enabled;
    let result = Command::new("wg-quick")
        .arg(if enabled { "down" } else { "up" })
        .arg(name.as_str())
        .output()
        .expect("Command failure");

    let popup = Dialog::text(String::from_utf8_lossy(&result.stderr))
        .button("OK", pop)
        .title(format!("Command output for {}", name));
    s.add_layer(popup);
}

//TODO get rid of this
fn pop(s: &mut Cursive) {
    s.pop_layer();
}
