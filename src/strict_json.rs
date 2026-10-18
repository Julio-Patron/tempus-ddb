//! Strict JSON parsing for documents that are verified.
//!
//! `serde_json::Value` silently keeps the *last* value of a repeated object key, while
//! other parsers (and a human reading the file) may see the first. A document with a
//! repeated key can therefore verify while being read differently elsewhere. Every
//! verifier entry point parses with [`parse`], which rejects repeated keys at any depth.

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

/// Marker present in the error message when a repeated object key is found.
pub(crate) const DUPLICATE_KEY_CODE: &str = "DUPLICATE_JSON_KEY";

struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number is not finite"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        Strict.deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(Strict)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "{DUPLICATE_KEY_CODE}: object key {key:?} appears more than once"
                )));
            }
            let value = access.next_value_seed(Strict)?;
            map.insert(key, value);
        }
        Ok(Value::Object(map))
    }
}

/// Parse `raw` as one JSON document, rejecting repeated object keys at any depth.
pub(crate) fn parse(raw: &str) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    let value = Strict.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// Marker present in errors and results for a number that is not an exact integer.
pub(crate) const NON_EXACT_NUMBER_CODE: &str = "NON_EXACT_NUMBER";

/// Path of the first number in `value` that is not an integer in i64/u64 range.
///
/// `serde_json` stores floats, and integers outside i64/u64, as f64, which silently rounds
/// them and lets many texts (`1e-1`, `0.10`, `...567891`) mean the same value. Signed
/// documents may therefore only hold integers in range; decimals and huge values must be
/// strings.
pub(crate) fn find_inexact_number(value: &Value) -> Option<String> {
    fn walk(value: &Value, path: &mut String) -> bool {
        match value {
            Value::Number(number) => !(number.is_i64() || number.is_u64()),
            Value::Array(items) => items.iter().enumerate().any(|(index, item)| {
                let len = path.len();
                path.push_str(&format!("[{index}]"));
                let found = walk(item, path);
                if !found {
                    path.truncate(len);
                }
                found
            }),
            Value::Object(map) => map.iter().any(|(key, item)| {
                let len = path.len();
                let key: String = key.chars().take(64).collect();
                path.push_str(&format!(".{key}"));
                let found = walk(item, path);
                if !found {
                    path.truncate(len);
                }
                found
            }),
            _ => false,
        }
    }
    let mut path = String::from("$");
    walk(value, &mut path).then_some(path)
}

/// Gate-side guard: refuse a document that holds a non-exact number.
pub(crate) fn reject_inexact_numbers(value: &Value, label: &str) -> Result<(), String> {
    match find_inexact_number(value) {
        Some(path) => Err(format!(
            "{NON_EXACT_NUMBER_CODE}: {label} holds a number at {path} that is not an integer in \
             the i64/u64 range; send decimals and larger values as strings"
        )),
        None => Ok(()),
    }
}

/// True when a parse error was caused by a repeated key.
pub(crate) fn is_duplicate_key(error: &serde_json::Error) -> bool {
    error.to_string().contains(DUPLICATE_KEY_CODE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_serde_json_when_keys_are_unique() {
        let raw = r#"{"a":[1,-2,3.5,"x",null,true],"b":{"c":{}}}"#;
        assert_eq!(
            parse(raw).unwrap(),
            serde_json::from_str::<Value>(raw).unwrap()
        );
    }

    #[test]
    fn rejects_repeated_keys_at_any_depth() {
        for raw in [
            r#"{"amount":"9999.00","amount":"25.00"}"#,
            r#"{"a":{"b":1,"b":2}}"#,
            r#"{"a":[{"k":1,"k":1}]}"#,
            r#"{"a":1,"\u0061":2}"#,
        ] {
            let error = parse(raw).unwrap_err();
            assert!(is_duplicate_key(&error), "{raw}: {error}");
        }
    }

    #[test]
    fn finds_floats_and_out_of_range_integers_with_their_path() {
        let ok = parse(r#"{"a":[1,-9223372036854775808,18446744073709551615],"s":"0.1"}"#).unwrap();
        assert_eq!(find_inexact_number(&ok), None);
        for (raw, path) in [
            (r#"{"f":0.1}"#, "$.f"),
            (
                r#"{"a":[1,{"h":123456789012345678901234567890}]}"#,
                "$.a[1].h",
            ),
            (r#"[18446744073709551616]"#, "$[0]"),
            (r#"{"k":-9223372036854775809}"#, "$.k"),
            (r#"{"x":2.0}"#, "$.x"),
            (r#"{"x":1e2}"#, "$.x"),
        ] {
            let value = parse(raw).unwrap();
            assert_eq!(find_inexact_number(&value).as_deref(), Some(path), "{raw}");
        }
    }

    #[test]
    fn same_key_in_sibling_objects_is_fine_and_trailing_data_is_rejected() {
        assert!(parse(r#"[{"k":1},{"k":2}]"#).is_ok());
        assert!(parse(r#"{"k":1} {"k":2}"#).is_err());
        assert!(!is_duplicate_key(&parse("{").unwrap_err()));
    }
}
