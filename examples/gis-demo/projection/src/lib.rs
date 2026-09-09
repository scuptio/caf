use serde::Serialize;

// ---------------------------------------------------------------------------
// Host ABI: a minimal, read-only payload filesystem scoped to the payload
// root. The host (browser runtime) implements these against the CAF file;
// the component never sees raw offsets or file formats.
// ---------------------------------------------------------------------------
#[link(wasm_import_module = "caf")]
unsafe extern "C" {
    fn open(path_ptr: u32, path_len: u32) -> i32;
    fn read(fd: i32, buf_ptr: u32, buf_len: u32) -> i32;
    fn close(fd: i32) -> i32;
    fn readdir(path_ptr: u32, path_len: u32, buf_ptr: u32, buf_len: u32) -> i32;
}

// ---------------------------------------------------------------------------
// Memory bridge: the host allocates a buffer in component memory, the
// component returns results as a packed (ptr | len<<32) value.
// ---------------------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "C" fn alloc(len: u32) -> u32 {
    if len == 0 {
        return 0;
    }
    let mut boxed: Box<[u8]> = vec![0u8; len as usize].into_boxed_slice();
    let ptr = boxed.as_mut_ptr() as u32;
    std::mem::forget(boxed);
    ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn dealloc(ptr: u32, len: u32) {
    if len == 0 || ptr == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, len as usize);
        let boxed: Box<[u8]> = Box::from_raw(slice as *mut [u8]);
        drop(boxed);
    }
}

fn pack_result(s: String) -> u64 {
    let boxed: Box<[u8]> = s.into_bytes().into_boxed_slice();
    let ptr = boxed.as_ptr() as u32;
    let len = boxed.len() as u32;
    std::mem::forget(boxed);
    (ptr as u64) | ((len as u64) << 32)
}

fn error_json(msg: String) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

// ---------------------------------------------------------------------------
// Normalized, format-agnostic feature model (the functional abstraction).
// ---------------------------------------------------------------------------
#[derive(Serialize)]
struct FeatureList {
    crs: String,
    features: Vec<Feature>,
}

#[derive(Serialize)]
struct Feature {
    layer: String,
    name: String,
    kind: String,
    coords: Coord,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Coord {
    Point([f64; 2]),
    Line(Vec<[f64; 2]>),
    Polygon(Vec<Vec<[f64; 2]>>),
    MultiPolygon(Vec<Vec<Vec<[f64; 2]>>>),
}

// ---------------------------------------------------------------------------
// Payload-fs helpers.
// ---------------------------------------------------------------------------
fn list_dir(path: &str) -> Result<Vec<String>, String> {
    let mut buf = vec![0u8; 8192];
    let n = unsafe {
        readdir(
            path.as_ptr() as u32,
            path.len() as u32,
            buf.as_mut_ptr() as u32,
            buf.len() as u32,
        )
    };
    if n < 0 {
        return Err(format!("readdir failed: {path}"));
    }
    let s = std::str::from_utf8(&buf[..n as usize]).map_err(|e| e.to_string())?;
    Ok(s.split('\n')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect())
}

fn read_file(path: &str) -> Result<Vec<u8>, String> {
    let fd = unsafe { open(path.as_ptr() as u32, path.len() as u32) };
    if fd < 0 {
        return Err(format!("open failed: {path}"));
    }
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = unsafe { read(fd, chunk.as_mut_ptr() as u32, chunk.len() as u32) };
        if n < 0 {
            unsafe { close(fd) };
            return Err(format!("read failed: {path}"));
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n as usize]);
    }
    unsafe { close(fd) };
    Ok(out)
}

// ---------------------------------------------------------------------------
// Capability: features() — discover and parse every payload file under
// /data, regardless of its physical format.
// ---------------------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "C" fn features() -> u64 {
    let result = match load_features() {
        Ok(features) => {
            let list = FeatureList {
                crs: "EPSG:4326".to_string(),
                features,
            };
            serde_json::to_string(&list).unwrap_or_else(|e| error_json(e.to_string()))
        }
        Err(e) => error_json(e),
    };
    pack_result(result)
}

fn load_features() -> Result<Vec<Feature>, String> {
    let mut features = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in list_dir("/data")? {
        let path = format!("/data/{entry}");
        let bytes = read_file(&path)?;
        let parsed = if bytes.starts_with(b"WKBSTREAM") {
            parse_wkb_impl(&bytes)?
        } else {
            parse_geojson_impl(&bytes)?
        };
        // Both formats carry the same logical dataset (one converted from the
        // other); keep each feature once regardless of which format it was read
        // from. This proves the component can read either carrier.
        for f in parsed.features {
            if seen.insert(f.name.clone()) {
                features.push(f);
            }
        }
    }
    Ok(features)
}

// ---------------------------------------------------------------------------
// GeoJSON parser.
// ---------------------------------------------------------------------------
fn parse_geojson_impl(bytes: &[u8]) -> Result<FeatureList, String> {
    use serde_json::Value;

    let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let arr = v
        .get("features")
        .and_then(|f| f.as_array())
        .ok_or("missing features array")?;

    let mut features = Vec::new();
    for f in arr {
        let props = f.get("properties");
        let layer = prop_str(props, &["layer", "continent"]);
        let name = prop_str(props, &["name", "name_long"]);
        let geom = f.get("geometry").ok_or("missing geometry")?;
        let gtype = geom
            .get("type")
            .and_then(|s| s.as_str())
            .unwrap_or("");
        let coords = geom.get("coordinates");
        let (kind, coord) = match gtype {
            "Point" => ("point".to_string(), Coord::Point(point_from(coords)?)),
            "LineString" => ("line".to_string(), Coord::Line(line_from(coords)?)),
            "Polygon" => ("polygon".to_string(), Coord::Polygon(polygon_from(coords)?)),
            "MultiPolygon" => (
                "multipolygon".to_string(),
                Coord::MultiPolygon(multipolygon_from(coords)?),
            ),
            other => return Err(format!("unsupported geometry: {other}")),
        };
        features.push(Feature {
            layer,
            name,
            kind,
            coords: coord,
        });
    }
    Ok(FeatureList {
        crs: "EPSG:4326".to_string(),
        features,
    })
}

fn prop_str(props: Option<&serde_json::Value>, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = props.and_then(|p| p.get(k)).and_then(|s| s.as_str()) {
            return s.to_string();
        }
    }
    String::new()
}

fn point_from(v: Option<&serde_json::Value>) -> Result<[f64; 2], String> {
    let arr = v
        .ok_or("missing coordinates")?
        .as_array()
        .ok_or("point not array")?;
    if arr.len() < 2 {
        return Err("point needs 2 coordinates".to_string());
    }
    let x = arr[0].as_f64().ok_or("invalid x")?;
    let y = arr[1].as_f64().ok_or("invalid y")?;
    Ok([x, y])
}

fn line_from(v: Option<&serde_json::Value>) -> Result<Vec<[f64; 2]>, String> {
    let arr = v.ok_or("missing coordinates")?.as_array().ok_or("line not array")?;
    arr.iter()
        .map(|p| point_from(Some(p)))
        .collect::<Result<Vec<_>, _>>()
}

fn polygon_from(v: Option<&serde_json::Value>) -> Result<Vec<Vec<[f64; 2]>>, String> {
    let arr = v
        .ok_or("missing coordinates")?
        .as_array()
        .ok_or("polygon not array")?;
    arr.iter()
        .map(|ring| line_from(Some(ring)))
        .collect::<Result<Vec<_>, _>>()
}

fn multipolygon_from(v: Option<&serde_json::Value>) -> Result<Vec<Vec<Vec<[f64; 2]>>>, String> {
    let arr = v
        .ok_or("missing coordinates")?
        .as_array()
        .ok_or("multipolygon not array")?;
    arr.iter()
        .map(|poly| polygon_from(Some(poly)))
        .collect::<Result<Vec<_>, _>>()
}

// ---------------------------------------------------------------------------
// WKB stream parser (little-endian only; the demo payload is LE).
// ---------------------------------------------------------------------------
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, String> {
        if self.pos + 1 > self.data.len() {
            return Err("unexpected eof".to_string());
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.data.len() {
            return Err("unexpected eof".to_string());
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_le_bytes(buf))
    }

    fn f64(&mut self) -> Result<f64, String> {
        if self.pos + 8 > self.data.len() {
            return Err("unexpected eof".to_string());
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(f64::from_le_bytes(buf))
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.data.len() {
            return Err("unexpected eof".to_string());
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

fn read_len_string(r: &mut Reader) -> Result<String, String> {
    let n = r.u32()? as usize;
    let b = r.bytes(n)?;
    std::str::from_utf8(b)
        .map(|s| s.to_string())
        .map_err(|e| e.to_string())
}

fn parse_wkb_impl(bytes: &[u8]) -> Result<FeatureList, String> {
    let mut r = Reader {
        data: bytes,
        pos: 0,
    };
    if r.bytes(9)? != b"WKBSTREAM" {
        return Err("bad wkb stream magic".to_string());
    }
    r.u8()?;
    r.u8()?; // version

    let mut features = Vec::new();
    while r.pos < r.data.len() {
        let layer = read_len_string(&mut r)?;
        let name = read_len_string(&mut r)?;
        let glen = r.u32()? as usize;
        let geom = r.bytes(glen)?;
        let (kind, coord) = parse_wkb_geom(geom)?;
        features.push(Feature {
            layer,
            name,
            kind,
            coords: coord,
        });
    }
    Ok(FeatureList {
        crs: "EPSG:4326".to_string(),
        features,
    })
}

fn parse_wkb_geom(bytes: &[u8]) -> Result<(String, Coord), String> {
    let mut r = Reader {
        data: bytes,
        pos: 0,
    };
    if r.u8()? != 0x01 {
        return Err("only little-endian WKB is supported".to_string());
    }
    match r.u32()? {
        1 => {
            let x = r.f64()?;
            let y = r.f64()?;
            Ok(("point".to_string(), Coord::Point([x, y])))
        }
        2 => {
            let n = r.u32()? as usize;
            let mut pts = Vec::with_capacity(n);
            for _ in 0..n {
                pts.push([r.f64()?, r.f64()?]);
            }
            Ok(("line".to_string(), Coord::Line(pts)))
        }
        3 => {
            let nr = r.u32()? as usize;
            let mut rings = Vec::with_capacity(nr);
            for _ in 0..nr {
                let np = r.u32()? as usize;
                let mut ring = Vec::with_capacity(np);
                for _ in 0..np {
                    ring.push([r.f64()?, r.f64()?]);
                }
                rings.push(ring);
            }
            Ok(("polygon".to_string(), Coord::Polygon(rings)))
        }
        6 => {
            let npoly = r.u32()? as usize;
            let mut polys = Vec::with_capacity(npoly);
            for _ in 0..npoly {
                let nr = r.u32()? as usize;
                let mut rings = Vec::with_capacity(nr);
                for _ in 0..nr {
                    let np = r.u32()? as usize;
                    let mut ring = Vec::with_capacity(np);
                    for _ in 0..np {
                        ring.push([r.f64()?, r.f64()?]);
                    }
                    rings.push(ring);
                }
                polys.push(rings);
            }
            Ok(("multipolygon".to_string(), Coord::MultiPolygon(polys)))
        }
        other => Err(format!("unsupported wkb type: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Capability: reproject — coordinate transform
// (WGS84 <-> Web Mercator / Equal Earth / Mollweide / Sinusoidal /
//  Hammer / Winkel I).
// ---------------------------------------------------------------------------
const EPSG_4326: i32 = 4326;
const EPSG_3857: i32 = 3857;
const EPSG_8857: i32 = 8857; // Equal Earth
const EPSG_54008: i32 = 54008; // Sinusoidal
const EPSG_54009: i32 = 54009; // Mollweide
const EPSG_54044: i32 = 54044; // Hammer
const EPSG_54045: i32 = 54045; // Winkel I

const MAX_LAT: f64 = 85.0511287798066;
const HALF_WORLD: f64 = 20037508.342789244;

fn normalize(code: i32) -> i32 {
    match code {
        900913 | 102100 | 102113 => EPSG_3857,
        other => other,
    }
}

fn to_mercator(lon: f64, lat: f64) -> (f64, f64) {
    let lat = lat.clamp(-MAX_LAT, MAX_LAT);
    let x = lon / 180.0 * HALF_WORLD;
    let y = (lat.to_radians() * 0.5 + std::f64::consts::FRAC_PI_4)
        .tan()
        .ln()
        / std::f64::consts::PI
        * HALF_WORLD;
    (x, y)
}

fn to_wgs84(x: f64, y: f64) -> (f64, f64) {
    let lon = x / HALF_WORLD * 180.0;
    let lat = (2.0 * (y / HALF_WORLD * std::f64::consts::PI).exp().atan()
        - std::f64::consts::FRAC_PI_2)
        .to_degrees();
    (lon, lat)
}

// Equal Earth (EPSG:8857) — equal-area pseudocylindrical projection.
// Reference: Savric, Patterson & Jenny (2018), "The Equal Earth map projection".
// Constants and formulas follow the PROJ `eqearth` implementation (spherical).
const EE_A1: f64 = 1.340264;
const EE_A2: f64 = -0.081106;
const EE_A3: f64 = 0.000893;
const EE_A4: f64 = 0.003796;
const EE_M: f64 = 0.866_025_403_784_438_6; // sqrt(3) / 2
const AUTHALIC_R: f64 = 6_371_008.7714; // authalic radius (m)
const EE_MAX_Y: f64 = 1.317_362_759_157_4; // 90 deg on unit sphere

fn to_equal_earth(lon: f64, lat: f64) -> (f64, f64) {
    let psi = (EE_M * lat.to_radians().sin()).asin();
    let psi2 = psi * psi;
    let psi6 = psi2 * psi2 * psi2;
    let denom = EE_A1 + 3.0 * EE_A2 * psi2 + psi6 * (7.0 * EE_A3 + 9.0 * EE_A4 * psi2);
    let x = lon.to_radians() * psi.cos() / (EE_M * denom) * AUTHALIC_R;
    let y = psi * (EE_A1 + EE_A2 * psi2 + psi6 * (EE_A3 + EE_A4 * psi2)) * AUTHALIC_R;
    (x, y)
}

fn from_equal_earth(x: f64, y: f64) -> (f64, f64) {
    let x = x / AUTHALIC_R;
    let y = (y / AUTHALIC_R).clamp(-EE_MAX_Y, EE_MAX_Y);

    // Newton-Raphson solve for psi.
    let mut yc = y;
    for _ in 0..12 {
        let y2 = yc * yc;
        let y6 = y2 * y2 * y2;
        let f = yc * (EE_A1 + EE_A2 * y2 + y6 * (EE_A3 + EE_A4 * y2)) - y;
        let fder = EE_A1 + 3.0 * EE_A2 * y2 + y6 * (7.0 * EE_A3 + 9.0 * EE_A4 * y2);
        let tol = f / fder;
        yc -= tol;
        if tol.abs() < 1e-11 {
            break;
        }
    }

    let y2 = yc * yc;
    let y6 = y2 * y2 * y2;
    let denom = EE_A1 + 3.0 * EE_A2 * y2 + y6 * (7.0 * EE_A3 + 9.0 * EE_A4 * y2);
    let lon = EE_M * x * denom / yc.cos();
    let lat = (yc.sin() / EE_M).asin();
    (lon.to_degrees(), lat.to_degrees())
}

// Sinusoidal (EPSG:54008) — equal-area pseudocylindrical, trivial formulas.
fn to_sinusoidal(lon: f64, lat: f64) -> (f64, f64) {
    let phi = lat.to_radians();
    let lam = lon.to_radians();
    (AUTHALIC_R * lam * phi.cos(), AUTHALIC_R * phi)
}

fn from_sinusoidal(x: f64, y: f64) -> (f64, f64) {
    let phi = y / AUTHALIC_R;
    let lam = x / (AUTHALIC_R * phi.cos());
    (lam.to_degrees(), phi.to_degrees())
}

// Mollweide (EPSG:54009) — equal-area pseudocylindrical.
// Reference formulas follow the PROJ `moll` implementation (spherical).
fn to_mollweide(lon: f64, lat: f64) -> (f64, f64) {
    let phi = lat.to_radians();
    let lam = lon.to_radians();
    let k = std::f64::consts::PI * phi.sin();

    // Newton solve for theta + sin(theta) = pi * sin(phi).
    let mut theta = phi;
    for _ in 0..30 {
        let v = (theta + theta.sin() - k) / (1.0 + theta.cos());
        theta -= v;
        if v.abs() < 1e-10 {
            break;
        }
    }
    let psi = theta * 0.5;

    let cx = 2.0 * std::f64::consts::SQRT_2 / std::f64::consts::PI;
    let x = AUTHALIC_R * cx * lam * psi.cos();
    let y = AUTHALIC_R * std::f64::consts::SQRT_2 * psi.sin();
    (x, y)
}

fn from_mollweide(x: f64, y: f64) -> (f64, f64) {
    let cx = 2.0 * std::f64::consts::SQRT_2 / std::f64::consts::PI;
    let psi = (y / (AUTHALIC_R * std::f64::consts::SQRT_2)).asin();
    let lam = x / (AUTHALIC_R * cx * psi.cos());
    let phi = ((2.0 * psi + (2.0 * psi).sin()) / std::f64::consts::PI).asin();
    (lam.to_degrees(), phi.to_degrees())
}

// Hammer (EPSG:54044) — equal-area (Hammer-Aitoff).
// Reference formulas follow the PROJ `hammer` implementation (w = 0.5, m = 1).
fn to_hammer(lon: f64, lat: f64) -> (f64, f64) {
    let phi = lat.to_radians();
    let lam = lon.to_radians();
    let d = (2.0 / (1.0 + phi.cos() * (lam * 0.5).cos())).sqrt();
    let x = AUTHALIC_R * 2.0 * d * phi.cos() * (lam * 0.5).sin();
    let y = AUTHALIC_R * d * phi.sin();
    (x, y)
}

fn from_hammer(x: f64, y: f64) -> (f64, f64) {
    let x = x / AUTHALIC_R;
    let y = y / AUTHALIC_R;
    let z = (1.0 - x * x / 16.0 - y * y / 4.0).sqrt();
    let lam = 2.0 * (x * z * 0.5).atan2(2.0 * z * z - 1.0);
    let phi = (z * y).asin();
    (lam.to_degrees(), phi.to_degrees())
}

// Winkel I (EPSG:54045) — compromise, closed-form both ways.
// Reference formulas follow the PROJ `wink1` implementation.
fn winkel_i_cosphi1() -> f64 {
    (2.0 / std::f64::consts::PI).acos()
}

fn to_winkel_i(lon: f64, lat: f64) -> (f64, f64) {
    let phi = lat.to_radians();
    let lam = lon.to_radians();
    let x = AUTHALIC_R * 0.5 * lam * (winkel_i_cosphi1() + phi.cos());
    let y = AUTHALIC_R * phi;
    (x, y)
}

fn from_winkel_i(x: f64, y: f64) -> (f64, f64) {
    let phi = y / AUTHALIC_R;
    let lam = 2.0 * x / (AUTHALIC_R * (winkel_i_cosphi1() + phi.cos()));
    (lam.to_degrees(), phi.to_degrees())
}

fn transform(x: f64, y: f64, from: i32, to: i32) -> (f64, f64) {
    let from = normalize(from);
    let to = normalize(to);
    if from == to {
        return (x, y);
    }
    let (lon, lat) = match from {
        EPSG_4326 => (x, y),
        EPSG_3857 => to_wgs84(x, y),
        EPSG_8857 => from_equal_earth(x, y),
        EPSG_54008 => from_sinusoidal(x, y),
        EPSG_54009 => from_mollweide(x, y),
        EPSG_54044 => from_hammer(x, y),
        EPSG_54045 => from_winkel_i(x, y),
        _ => (x, y),
    };
    match to {
        EPSG_4326 => (lon, lat),
        EPSG_3857 => to_mercator(lon, lat),
        EPSG_8857 => to_equal_earth(lon, lat),
        EPSG_54008 => to_sinusoidal(lon, lat),
        EPSG_54009 => to_mollweide(lon, lat),
        EPSG_54044 => to_hammer(lon, lat),
        EPSG_54045 => to_winkel_i(lon, lat),
        _ => (lon, lat),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn reproject_x(x: f64, y: f64, from: i32, to: i32) -> f64 {
    transform(x, y, from, to).0
}

#[unsafe(no_mangle)]
pub extern "C" fn reproject_y(x: f64, y: f64, from: i32, to: i32) -> f64 {
    transform(x, y, from, to).1
}
