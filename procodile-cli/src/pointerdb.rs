//! A SQLite file holding pointer maps and the current pointer scan results, so the
//! multi-run workflow (save a map per run, then intersect) survives across sessions.
//!
//! Maps are stored as blobs in the library's binary format; results are stored one path
//! per row, as the address expression they display as.

use std::path::Path;

use procodile::Address;
use procodile::scan::{PointerMap, PointerPath};

/// A saved map, without its data.
#[derive(Debug, Clone)]
pub struct MapInfo {
    pub id: i64,
    pub label: String,
    pub process: String,
    pub pid: u32,
    /// The address of the value when the map was taken.
    pub target: Address,
    pub created: String,
    pub pointers: usize,
}

#[cfg(feature = "sqlite")]
pub use imp::PointerDb;

#[cfg(feature = "sqlite")]
mod imp {
    use std::path::PathBuf;

    use rusqlite::{Connection, OptionalExtension, params};

    use super::*;

    const SCHEMA_VERSION: i64 = 1;

    pub struct PointerDb {
        conn: Connection,
        path: PathBuf,
    }

    fn err(e: rusqlite::Error) -> String {
        format!("pointer database: {e}")
    }

    impl PointerDb {
        pub fn open(path: &Path) -> Result<PointerDb, String> {
            let conn = Connection::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(err)?;
            match version {
                0 => conn
                    .execute_batch(
                        "BEGIN;
                         CREATE TABLE maps (
                             id INTEGER PRIMARY KEY,
                             label TEXT NOT NULL,
                             process TEXT NOT NULL,
                             pid INTEGER NOT NULL,
                             target INTEGER NOT NULL,
                             created TEXT NOT NULL DEFAULT (datetime('now')),
                             pointers INTEGER NOT NULL,
                             data BLOB NOT NULL
                         );
                         CREATE TABLE paths (
                             id INTEGER PRIMARY KEY,
                             path TEXT NOT NULL,
                             module TEXT NOT NULL,
                             depth INTEGER NOT NULL
                         );
                         CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
                         PRAGMA user_version = 1;
                         COMMIT;",
                    )
                    .map_err(err)?,
                SCHEMA_VERSION => {}
                v => {
                    return Err(format!(
                        "{}: unsupported pointer database version {v}",
                        path.display()
                    ));
                }
            }
            Ok(PointerDb {
                conn,
                path: path.to_owned(),
            })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn save_map(
            &self,
            label: &str,
            process: &str,
            pid: u32,
            target: Address,
            map: &PointerMap,
        ) -> Result<i64, String> {
            let mut data = Vec::new();
            map.write_to(&mut data).map_err(|e| e.to_string())?;
            self.conn
                .execute(
                    "INSERT INTO maps (label, process, pid, target, pointers, data)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        label,
                        process,
                        pid,
                        target.get() as i64,
                        map.len() as i64,
                        data
                    ],
                )
                .map_err(err)?;
            Ok(self.conn.last_insert_rowid())
        }

        pub fn maps(&self) -> Result<Vec<MapInfo>, String> {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT id, label, process, pid, target, created, pointers
                     FROM maps ORDER BY id",
                )
                .map_err(err)?;
            stmt.query_map([], map_info)
                .map_err(err)?
                .collect::<Result<_, _>>()
                .map_err(err)
        }

        pub fn load_map(&self, id: i64) -> Result<(MapInfo, PointerMap), String> {
            let row = self
                .conn
                .query_row(
                    "SELECT id, label, process, pid, target, created, pointers, data
                     FROM maps WHERE id = ?1",
                    [id],
                    |r| Ok((map_info(r)?, r.get::<_, Vec<u8>>(7)?)),
                )
                .optional()
                .map_err(err)?;
            let (info, data) = row.ok_or_else(|| format!("no pointer map {id}"))?;
            let map = PointerMap::read_from(data.as_slice())
                .map_err(|e| format!("pointer map {id}: {e}"))?;
            Ok((info, map))
        }

        pub fn remove_map(&self, id: i64) -> Result<bool, String> {
            let n = self
                .conn
                .execute("DELETE FROM maps WHERE id = ?1", [id])
                .map_err(err)?;
            Ok(n > 0)
        }

        /// Replaces the stored results.
        pub fn save_paths(&mut self, target: Address, paths: &[PointerPath]) -> Result<(), String> {
            let tx = self.conn.transaction().map_err(err)?;
            tx.execute("DELETE FROM paths", []).map_err(err)?;
            {
                let mut insert = tx
                    .prepare("INSERT INTO paths (path, module, depth) VALUES (?1, ?2, ?3)")
                    .map_err(err)?;
                for p in paths {
                    insert
                        .execute(params![p.to_string(), p.module, p.depth() as i64])
                        .map_err(err)?;
                }
            }
            tx.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('target', ?1)",
                [target.get() as i64],
            )
            .map_err(err)?;
            tx.commit().map_err(err)
        }

        pub fn clear_paths(&mut self) -> Result<(), String> {
            self.conn
                .execute_batch("DELETE FROM paths; DELETE FROM meta WHERE key = 'target';")
                .map_err(err)
        }

        /// The stored results, if any.
        pub fn load_paths(&self) -> Result<Option<(Address, Vec<PointerPath>)>, String> {
            let target: Option<i64> = self
                .conn
                .query_row("SELECT value FROM meta WHERE key = 'target'", [], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(err)?;
            let Some(target) = target else {
                return Ok(None);
            };
            let mut stmt = self
                .conn
                .prepare("SELECT path FROM paths ORDER BY id")
                .map_err(err)?;
            let texts: Vec<String> = stmt
                .query_map([], |r| r.get(0))
                .map_err(err)?
                .collect::<Result<_, _>>()
                .map_err(err)?;
            let paths = texts
                .iter()
                .map(|t| t.parse::<PointerPath>().map_err(|e| e.to_string()))
                .collect::<Result<_, _>>()?;
            Ok(Some((Address::new(target as usize), paths)))
        }
    }

    fn map_info(r: &rusqlite::Row<'_>) -> rusqlite::Result<MapInfo> {
        Ok(MapInfo {
            id: r.get(0)?,
            label: r.get(1)?,
            process: r.get(2)?,
            pid: r.get(3)?,
            target: Address::new(r.get::<_, i64>(4)? as usize),
            created: r.get(5)?,
            pointers: r.get::<_, i64>(6)? as usize,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn stores_maps_and_paths() {
            let dir = std::env::temp_dir().join(format!("procodile-db-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("test.db");
            let _ = std::fs::remove_file(&path);

            let handle = procodile::ProcessHandle::open_current().unwrap();
            let map = PointerMap::build(&handle, &Default::default(), None).unwrap();
            let paths = vec![
                "[[a.so+0x10]+0x8]+0x4".parse::<PointerPath>().unwrap(),
                "[\"b-c.so\"+0x0]+0x0".parse().unwrap(),
            ];
            {
                let mut db = PointerDb::open(&path).unwrap();
                let id = db
                    .save_map("run 1", "test", 42, Address::new(0x1000), &map)
                    .unwrap();
                db.save_paths(Address::new(0x1000), &paths).unwrap();

                let (info, loaded) = db.load_map(id).unwrap();
                assert_eq!(info.label, "run 1");
                assert_eq!(info.target, Address::new(0x1000));
                assert_eq!(info.pointers, map.len());
                assert_eq!(loaded, map);
                assert!(db.load_map(id + 1).is_err());
            }

            // Reopening finds everything again.
            let mut db = PointerDb::open(&path).unwrap();
            assert_eq!(db.maps().unwrap().len(), 1);
            assert_eq!(
                db.load_paths().unwrap(),
                Some((Address::new(0x1000), paths))
            );
            db.clear_paths().unwrap();
            assert_eq!(db.load_paths().unwrap(), None);
            assert!(db.remove_map(db.maps().unwrap()[0].id).unwrap());
            assert!(db.maps().unwrap().is_empty());

            drop(db);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

/// Stand-in when built without the `sqlite` feature, so callers need no `cfg`.
#[cfg(not(feature = "sqlite"))]
pub struct PointerDb(std::convert::Infallible);

#[cfg(not(feature = "sqlite"))]
#[allow(clippy::unused_self)]
impl PointerDb {
    pub fn open(_: &Path) -> Result<PointerDb, String> {
        Err("procodile was built without the `sqlite` feature".into())
    }

    pub fn path(&self) -> &Path {
        match self.0 {}
    }

    pub fn save_map(
        &self,
        _: &str,
        _: &str,
        _: u32,
        _: Address,
        _: &PointerMap,
    ) -> Result<i64, String> {
        match self.0 {}
    }

    pub fn maps(&self) -> Result<Vec<MapInfo>, String> {
        match self.0 {}
    }

    pub fn load_map(&self, _: i64) -> Result<(MapInfo, PointerMap), String> {
        match self.0 {}
    }

    pub fn remove_map(&self, _: i64) -> Result<bool, String> {
        match self.0 {}
    }

    pub fn save_paths(&mut self, _: Address, _: &[PointerPath]) -> Result<(), String> {
        match self.0 {}
    }

    pub fn clear_paths(&mut self) -> Result<(), String> {
        match self.0 {}
    }

    pub fn load_paths(&self) -> Result<Option<(Address, Vec<PointerPath>)>, String> {
        match self.0 {}
    }
}
