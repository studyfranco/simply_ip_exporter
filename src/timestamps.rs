//! UTC clock and stable ISO-8601 serialization for timestamps on the wire.

use serde::{Deserialize, Deserializer, Serializer, de, ser};
use time::format_description::{BorrowedFormatItem, well_known::Rfc3339};
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};

const SECONDS: &[BorrowedFormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
const FRACTIONAL: &[BorrowedFormatItem<'_>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]");

/// Returns the current UTC time with the offset omitted.
#[must_use]
pub fn now_utc() -> PrimitiveDateTime {
    let now = OffsetDateTime::now_utc();
    PrimitiveDateTime::new(now.date(), now.time())
}

pub(crate) fn parse_rfc3339(value: &str) -> Option<PrimitiveDateTime> {
    let utc = OffsetDateTime::parse(value, &Rfc3339)
        .ok()?
        .checked_to_offset(UtcOffset::UTC)?;
    Some(PrimitiveDateTime::new(utc.date(), utc.time()))
}

fn parse(value: &str) -> Option<PrimitiveDateTime> {
    PrimitiveDateTime::parse(value, SECONDS)
        .or_else(|_| PrimitiveDateTime::parse(value, FRACTIONAL))
        .ok()
        .or_else(|| parse_rfc3339(value))
}

fn format(value: PrimitiveDateTime) -> Result<String, time::error::Format> {
    let mut output = value.format(SECONDS)?;
    let nanos = value.nanosecond();
    if nanos != 0 {
        use std::fmt::Write as _;
        let (digits, fraction) = if nanos.is_multiple_of(1_000_000) {
            (3, nanos / 1_000_000)
        } else if nanos.is_multiple_of(1_000) {
            (6, nanos / 1_000)
        } else {
            (9, nanos)
        };
        write!(output, ".{fraction:0digits$}").map_err(std::io::Error::other)?;
    }
    Ok(output)
}

pub(crate) fn serialize<S>(value: &PrimitiveDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format(*value).map_err(ser::Error::custom)?)
}

pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<PrimitiveDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    parse(&String::deserialize(deserializer)?)
        .ok_or_else(|| de::Error::custom("invalid ISO-8601 timestamp"))
}

pub(crate) mod option {
    use super::{Deserialize, Deserializer, PrimitiveDateTime, Serializer, de, format, parse, ser};

    pub(crate) fn serialize<'a, S>(
        value: impl Into<Option<&'a PrimitiveDateTime>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value.into() {
            Some(value) => serializer.serialize_some(&format(*value).map_err(ser::Error::custom)?),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<PrimitiveDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .as_deref()
            .map(|value| {
                parse(value).ok_or_else(|| de::Error::custom("invalid ISO-8601 timestamp"))
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_fraction_width_and_normalizes_offsets() {
        for (input, expected) in [
            ("2026-08-11T10:26:46", "2026-08-11T10:26:46"),
            ("2026-08-11T10:26:46.1Z", "2026-08-11T10:26:46.100"),
            (
                "2026-08-11T10:26:46.123450+00:00",
                "2026-08-11T10:26:46.123450",
            ),
            (
                "2026-08-11T11:26:46.123456780+01:00",
                "2026-08-11T10:26:46.123456780",
            ),
        ] {
            assert_eq!(format(parse(input).unwrap()).unwrap(), expected);
        }
    }
}
