//! Transforms version requirements as provided by the `semver` crate
//! into a bunch of `[start; end)` ranges where the starting version
//! is always inclusive, and the end version is always exclusive.
//!
//! This is used for exporting to OSV format.
//! This also allows handling pre-releases correctly,
//! which `semver` crate does not allow doing directly.
//! See https://github.com/steveklabnik/semver/issues/172

use semver::Version;
use semver::version_req::Op;

/// A range of affected versions.
/// If any of the bounds is unspecified, that means ALL versions
/// in that direction are affected.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OsvRange {
    /// Inclusive
    start: Option<Version>,
    /// Exclusive
    end: Option<Version>,
}

/// A range of unaffected versions, used by either `patched`
/// or `unaffected` fields in the security advisory.
/// Bounds may be inclusive or exclusive.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct UnaffectedRange {
    start: Bound,
    end: Bound,
}

impl Default for UnaffectedRange {
    fn default() -> Self {
        UnaffectedRange {start: Bound::Unbounded, end: Bound::Unbounded}
    }
}

impl UnaffectedRange {
    fn is_valid(&self) -> bool {
        let r = self;
        if r.start == Bound::Unbounded || r.end == Bound::Unbounded {
            true
        } else if r.start.version().unwrap() < r.end.version().unwrap() {
            true
        } else {
            match (&r.start, &r.end) {
                (Bound::Exclusive(v_start), Bound::Inclusive(v_end)) => v_start == v_end,
                (Bound::Inclusive(v_start), Bound::Exclusive(v_end)) => v_start == v_end,
                (Bound::Inclusive(v_start), Bound::Inclusive(v_end)) => v_start == v_end,
                (_, _) => false
            }
        }
    }

    /// Requires ranges to be valid (i.e. `start <= end`) to work properly
    /// TODO: fancy checked constructor for ranges or something
    fn overlaps(&self, other: &UnaffectedRange) -> bool {
        assert!(self.is_valid());
        assert!(other.is_valid());
        // range check for well-formed ranges is `(Start1 <= End2) && (End1 >= Start2)`
        // but it's complicated by our inclusive/exclusive bounds and unbounded ranges
        match (self.start.version(), other.end.version()) {
            (Some(start1), Some(end2)) => {
                if end2 < start1 {
                    return false
                } else if end2 == start1 {
                    match (&self.start, &other.end) {
                        (Bound::Inclusive(_), Bound::Inclusive(_)) => (), //keep going
                        _ => return false,
                    }
                }
            },
            _ => (), // if one of these bounds is None, keep going
        }
        true // TODO
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Bound {
    Unbounded,
    Exclusive(Version),
    Inclusive(Version)
}

impl Bound {
    fn version(&self) -> Option<&Version> {
        match &self {
            Bound::Unbounded => None,
            Bound::Exclusive(v) => Some(v),
            Bound::Inclusive(v) => Some(v),
        }
    }
}

// To keep the algorithm simple, we make several assumptions:
// 1. There are at most two version boundaries per `VersionReq`.
//    This means that stuff like `>= 1.0 < 1.5 || >= 2.0 || 2.5`
//    is not supported. We use a list of ranges for that instead...
//    Which is probably not a great idea in retrospect.
// 2. There is at most one upper and at most one lower bound in each range.
//    Stuff like `>= 1.0, >= 2.0` is nonsense.
// This is fine for the advisory database as of May 2021.
impl From<semver::Range> for UnaffectedRange {
    fn from(input: semver::Range) -> Self {
        assert!(input.predicates.len() <= 2, "Unsupported version specification: too many predicates");
        let mut result = UnaffectedRange::default();
        for predicate in input.predicates {
            match predicate.op {
                Op::Ex => {todo!()}
                Op::Gt => {
                    assert!(result.start == Bound::Unbounded, "More than one lower bound in the same range!");
                    result.start = Bound::Exclusive(predicate.into());
                }
                Op::GtEq => {
                    assert!(result.start == Bound::Unbounded, "More than one lower bound in the same range!");
                    result.start = Bound::Inclusive(predicate.into());
                }
                Op::Lt => {
                    assert!(result.end == Bound::Unbounded, "More than one upper bound in the same range!");
                    result.end = Bound::Exclusive(predicate.into());
                }
                Op::LtEq => {
                    assert!(result.end == Bound::Unbounded, "More than one upper bound in the same range!");
                    result.end = Bound::Inclusive(predicate.into());
                }
            }
        }
        assert!(result.is_valid());
        result
    }
}