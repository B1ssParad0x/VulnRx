//! City positions for hospitals whose certified product is named by a CVE record.
//!
//! The blank US map has no geographic grid, so a fitted projection places a city
//! inside its state. A hospital with no city falls back to the state center.

#[derive(Clone, Copy)]
struct StateBox {
    code: &'static str,
    cx: f64,
    cy: f64,
    x0: f64,
    x1: f64,
    y0: f64,
    y1: f64,
}

#[derive(Clone, Copy)]
struct City {
    state: &'static str,
    city: &'static str,
    lat: f64,
    lon: f64,
}

pub(crate) struct MapPin {
    pub id: String,
    pub name: String,
    pub x: String,
    pub y: String,
}

pub(crate) fn pin_position(state: &str, city: Option<&str>) -> Option<(f64, f64)> {
    let bounds = state_box(state)?;
    let projected = city
        .and_then(|name| city_lat_lon(state, name))
        .map(|(lat, lon)| project(lat, lon));
    let (x, y) = projected.unwrap_or((bounds.cx, bounds.cy));
    Some((
        clamp_in(x, bounds.x0, bounds.x1),
        clamp_in(y, bounds.y0, bounds.y1),
    ))
}

fn project(lat: f64, lon: f64) -> (f64, f64) {
    // Fitted from this map's state centers. x grows east, y grows south.
    let x = 16.17843459530221 * lon + 0.10480997947635018 * lat + 2027.4148993178783;
    let y = 0.1324239973602026 * lon - 24.540423472024926 * lat + 1225.2735557157553;
    (x, y)
}

fn clamp_in(value: f64, lo: f64, hi: f64) -> f64 {
    if hi - lo < 16.0 {
        (lo + hi) / 2.0
    } else {
        value.clamp(lo + 6.0, hi - 6.0)
    }
}

fn city_lat_lon(state: &str, city: &str) -> Option<(f64, f64)> {
    let city = city.trim();
    CITIES.iter().find_map(|row| {
        if row.state.eq_ignore_ascii_case(state) && row.city.eq_ignore_ascii_case(city) {
            Some((row.lat, row.lon))
        } else {
            None
        }
    })
}

fn state_box(state: &str) -> Option<&'static StateBox> {
    STATES.iter().find(|row| row.code.eq_ignore_ascii_case(state))
}

const CITIES: &[City] = &[
    City { state: "AR", city: "CONWAY", lat: 35.0887, lon: -92.4421 },
    City { state: "AR", city: "DARDANELLE", lat: 35.2231, lon: -93.1560 },
    City { state: "AZ", city: "SACATON", lat: 33.0759, lon: -111.7407 },
    City { state: "CO", city: "RIFLE", lat: 39.5347, lon: -107.7831 },
    City { state: "CO", city: "MONTROSE", lat: 38.4783, lon: -107.8762 },
    City { state: "CO", city: "TRINIDAD", lat: 37.1695, lon: -104.5005 },
    City { state: "GA", city: "DALTON", lat: 34.7698, lon: -84.9702 },
    City { state: "LA", city: "BATON ROUGE", lat: 30.4515, lon: -91.1871 },
    City { state: "NY", city: "ITHACA", lat: 42.4430, lon: -76.5019 },
    City { state: "NY", city: "ONEIDA", lat: 43.0926, lon: -75.6513 },
    City { state: "NY", city: "WATERTOWN", lat: 43.9748, lon: -75.9108 },
    City { state: "OH", city: "LIMA", lat: 40.7426, lon: -84.1052 },
    City { state: "PA", city: "STATE COLLEGE", lat: 40.7934, lon: -77.8600 },
    City { state: "PA", city: "BENSALEM", lat: 40.1045, lon: -74.9513 },
    City { state: "TN", city: "BROWNSVILLE", lat: 35.5937, lon: -89.2623 },
    City { state: "TN", city: "LEXINGTON", lat: 35.6515, lon: -88.3928 },
    City { state: "TN", city: "ERIN", lat: 36.3167, lon: -87.6981 },
];

const STATES: &[StateBox] = &[
    StateBox { code: "AL", cx: 654.2, cy: 415.5, x0: 620.9, x1: 687.6, y0: 361.1, y1: 470.0 },
    StateBox { code: "AK", cx: 114.0, cy: 510.2, x0: 9.8, x1: 218.2, y0: 432.4, y1: 588.1 },
    StateBox { code: "AZ", cx: 194.4, cy: 366.0, x0: 134.9, x1: 253.8, y0: 296.8, y1: 435.1 },
    StateBox { code: "AR", cx: 548.8, cy: 374.3, x0: 504.5, x1: 593.2, y0: 334.4, y1: 414.2 },
    StateBox { code: "CA", cx: 84.3, cy: 267.8, x0: 14.0, x1: 154.7, y0: 147.9, y1: 387.6 },
    StateBox { code: "CO", cx: 317.3, cy: 273.0, x0: 253.8, x1: 380.8, y0: 222.7, y1: 323.3 },
    StateBox { code: "CT", cx: 858.8, cy: 179.9, x0: 843.8, x1: 873.9, y0: 165.2, y1: 194.7 },
    StateBox { code: "DE", cx: 827.1, cy: 241.9, x0: 817.9, x1: 836.4, y0: 226.6, y1: 257.2 },
    StateBox { code: "FL", cx: 718.1, cy: 511.6, x0: 638.3, x1: 798.0, y0: 443.5, y1: 579.6 },
    StateBox { code: "GA", cx: 714.2, cy: 404.8, x0: 666.6, x1: 761.8, y0: 355.2, y1: 454.4 },
    StateBox { code: "HI", cx: 284.1, cy: 546.7, x0: 227.7, x1: 340.6, y0: 509.8, y1: 583.5 },
    StateBox { code: "ID", cx: 193.0, cy: 111.7, x0: 140.9, x1: 245.0, y0: 27.5, y1: 196.0 },
    StateBox { code: "IL", cx: 590.5, cy: 260.8, x0: 555.4, x1: 625.5, y0: 199.2, y1: 322.5 },
    StateBox { code: "IN", cx: 644.2, cy: 256.7, x0: 617.4, x1: 670.9, y0: 209.8, y1: 303.5 },
    StateBox { code: "IA", cx: 523.4, cy: 215.1, x0: 471.2, x1: 575.7, y0: 180.4, y1: 249.7 },
    StateBox { code: "KS", cx: 439.5, cy: 291.3, x0: 374.6, x1: 504.3, y0: 256.3, y1: 326.3 },
    StateBox { code: "KY", cx: 658.1, cy: 301.0, x0: 593.4, x1: 722.7, y0: 268.2, y1: 333.8 },
    StateBox { code: "LA", cx: 566.1, cy: 456.2, x0: 516.7, x1: 615.6, y0: 412.9, y1: 499.6 },
    StateBox { code: "ME", cx: 895.2, cy: 87.5, x0: 863.1, x1: 927.4, y0: 36.7, y1: 138.3 },
    StateBox { code: "MD", cx: 796.9, cy: 249.9, x0: 757.4, x1: 836.4, y0: 230.1, y1: 269.7 },
    StateBox { code: "MA", cx: 873.7, cy: 159.4, x0: 843.1, x1: 904.3, y0: 142.8, y1: 176.0 },
    StateBox { code: "MI", cx: 631.9, cy: 144.1, x0: 565.6, x1: 698.3, y0: 74.9, y1: 213.2 },
    StateBox { code: "MN", cx: 520.2, cy: 117.8, x0: 462.3, x1: 578.1, y0: 53.7, y1: 182.0 },
    StateBox { code: "MS", cx: 594.0, cy: 419.4, x0: 562.8, x1: 625.3, y0: 365.1, y1: 473.6 },
    StateBox { code: "MO", cx: 542.9, cy: 295.3, x0: 484.5, x1: 601.2, y0: 244.9, y1: 345.7 },
    StateBox { code: "MT", cx: 273.2, cy: 87.1, x0: 184.0, x1: 362.5, y0: 30.5, y1: 143.7 },
    StateBox { code: "NE", cx: 419.6, cy: 223.5, x0: 347.7, x1: 491.5, y0: 187.6, y1: 259.5 },
    StateBox { code: "NV", cx: 133.1, cy: 252.3, x0: 77.5, x1: 188.6, y0: 166.5, y1: 338.1 },
    StateBox { code: "NH", cx: 867.4, cy: 122.2, x0: 852.9, x1: 881.9, y0: 91.9, y1: 152.6 },
    StateBox { code: "NJ", cx: 834.1, cy: 217.4, x0: 822.5, x1: 845.6, y0: 190.5, y1: 244.4 },
    StateBox { code: "NM", cx: 297.2, cy: 374.1, x0: 236.4, x1: 358.1, y0: 311.0, y1: 437.3 },
    StateBox { code: "NY", cx: 809.2, cy: 157.3, x0: 743.0, x1: 875.4, y0: 107.0, y1: 207.6 },
    StateBox { code: "NC", cx: 766.8, cy: 333.5, x0: 689.5, x1: 844.1, y0: 299.7, y1: 367.3 },
    StateBox { code: "ND", cx: 414.7, cy: 92.3, x0: 357.3, x1: 472.1, y0: 56.3, y1: 128.4 },
    StateBox { code: "OH", cx: 700.1, cy: 237.3, x0: 663.4, x1: 736.8, y0: 195.2, y1: 279.4 },
    StateBox { code: "OK", cx: 433.0, cy: 361.4, x0: 357.5, x1: 508.6, y0: 322.3, y1: 400.5 },
    StateBox { code: "OR", cx: 96.8, cy: 118.6, x0: 26.5, x1: 167.1, y0: 59.5, y1: 177.7 },
    StateBox { code: "PA", cx: 782.7, cy: 212.0, x0: 731.9, x1: 833.5, y0: 179.1, y1: 244.8 },
    StateBox { code: "RI", cx: 877.7, cy: 173.2, x0: 870.7, x1: 884.6, y0: 163.5, y1: 182.9 },
    StateBox { code: "SC", cx: 752.1, cy: 380.2, x0: 707.5, x1: 796.8, y0: 346.7, y1: 413.7 },
    StateBox { code: "SD", cx: 412.6, cy: 163.7, x0: 351.4, x1: 473.9, y0: 123.0, y1: 204.4 },
    StateBox { code: "TN", cx: 657.0, cy: 342.0, x0: 582.6, x1: 731.4, y0: 316.3, y1: 367.7 },
    StateBox { code: "TX", cx: 404.6, cy: 452.5, x0: 282.3, x1: 526.8, y0: 332.9, y1: 572.1 },
    StateBox { code: "UT", cx: 216.4, cy: 249.4, x0: 167.6, x1: 265.3, y0: 187.8, y1: 311.0 },
    StateBox { code: "VT", cx: 845.3, cy: 127.7, x0: 830.6, x1: 860.1, y0: 100.1, y1: 155.3 },
    StateBox { code: "VA", cx: 766.5, cy: 282.9, x0: 697.7, x1: 835.3, y0: 244.7, y1: 321.1 },
    StateBox { code: "WA", cx: 116.0, cy: 48.5, x0: 57.4, x1: 174.6, y0: 5.2, y1: 91.9 },
    StateBox { code: "WV", cx: 748.7, cy: 264.2, x0: 709.2, x1: 788.2, y0: 225.1, y1: 303.2 },
    StateBox { code: "WI", cx: 575.7, cy: 151.5, x0: 528.6, x1: 622.9, y0: 101.0, y1: 202.0 },
    StateBox { code: "WY", cx: 294.2, cy: 181.1, x0: 233.2, x1: 355.3, y0: 130.5, y1: 231.8 },
    StateBox { code: "DC", cx: 801.7, cy: 252.4, x0: 799.9, x1: 803.5, y0: 250.2, y1: 254.6 },
];

#[cfg(test)]
mod tests {
    use super::pin_position;

    #[test]
    fn montrose_lands_in_colorado() {
        let (x, y) = pin_position("CO", Some("MONTROSE")).unwrap();
        assert!((253.8..=380.8).contains(&x));
        assert!((222.7..=323.3).contains(&y));
    }

    #[test]
    fn dalton_is_kept_inside_georgia() {
        let (x, y) = pin_position("GA", Some("DALTON")).unwrap();
        assert!((666.6..=761.8).contains(&x));
        assert!((355.2..=454.4).contains(&y));
    }

    #[test]
    fn a_hospital_without_a_city_uses_the_state_center() {
        let (x, y) = pin_position("AL", None).unwrap();
        assert!((x - 654.2).abs() < 0.1);
        assert!((y - 415.5).abs() < 0.1);
    }
}
