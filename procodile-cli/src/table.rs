//! The address table: saved addresses with a type, like a Cheat Engine cheat table.

use std::path::Path;

use procodile::freeze::FreezeId;
use procodile::scan::ValueType;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    #[serde(default)]
    pub description: String,
    /// The address expression, re-evaluated on every use so pointer paths and module
    /// offsets keep working when the target moves things around.
    pub address: String,
    #[serde(rename = "type", with = "value_type")]
    pub value_type: ValueType,
    #[serde(skip)]
    pub frozen: Option<FreezeId>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Table {
    #[serde(default, rename = "entry")]
    pub entries: Vec<Entry>,
}

impl Table {
    pub fn get(&self, index: usize) -> Result<&Entry, String> {
        self.entries
            .get(index)
            .ok_or_else(|| format!("no address table entry ${index}"))
    }

    pub fn get_mut(&mut self, index: usize) -> Result<&mut Entry, String> {
        self.entries
            .get_mut(index)
            .ok_or_else(|| format!("no address table entry ${index}"))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn load(path: &Path) -> Result<Table, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let table: Table = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        for entry in &table.entries {
            crate::expr::parse(&entry.address)?;
        }
        Ok(table)
    }
}

mod value_type {
    use procodile::scan::ValueType;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(ty: &ValueType, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(ty.name())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ValueType, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let table = Table {
            entries: vec![Entry {
                description: "health".into(),
                address: "[game.exe+0x10]+8".into(),
                value_type: ValueType::F32,
                frozen: None,
            }],
        };
        let text = toml::to_string_pretty(&table).unwrap();
        assert!(text.contains("type = \"f32\""));
        let back: Table = toml::from_str(&text).unwrap();
        assert_eq!(back.entries[0].address, "[game.exe+0x10]+8");
        assert_eq!(back.entries[0].value_type, ValueType::F32);
    }
}
