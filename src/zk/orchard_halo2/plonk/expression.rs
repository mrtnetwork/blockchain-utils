//! Implements plonk/expression logic.
//! LE wire bytes; `to_debug_string()` uses `format!` with BE `0x` hex
//! (LE bytes reversed), mirroring the reference
//! `BytesUtils.toHexString(b.toBytes().reversed.toList(), prefix: "0x")`.
//! Result style, no `assert!`: fallible ops (`try_add`, `try_sub`, `try_mul`,
//! `extract_simple_selector`) return `Halo2Result`.

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String};
// `Vec` is prelude under `std`; import from `alloc` only for `no_std`.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

use crate::zk::orchard_halo2::error::{Halo2Error, Halo2Result};
use crate::zk::orchard_halo2::field::PallasFp;
use crate::zk::orchard_halo2::plonk::column::Selector;
use crate::zk::orchard_halo2::poly::poly::Rotation;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Query {
    pub index: usize,
    pub column_index: usize,
    pub rotation: Rotation,
}

impl Query {
    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        alloc::format!(
            "{{ query_index: {}, column_index: {}, rotation: {} }}",
            self.index,
            self.column_index,
            self.rotation.to_debug_string()
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ExpressionType {
    Constant = 1,
    Negated = 2,
    Sum = 3,
    Product = 4,
    Scaled = 6,
    Fixed = 7,
    Advice = 8,
    Instance = 9,
    Selector = 10,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Expression {
    Constant(PallasFp),
    Selector(Selector),
    Fixed(Query),
    Advice(Query),
    Instance(Query),
    Negated(Box<Expression>),
    Sum(Box<Expression>, Box<Expression>),
    Product(Box<Expression>, Box<Expression>),
    Scaled(Box<Expression>, PallasFp),
}

impl Expression {
    pub fn constant(v: PallasFp) -> Self {
        Self::Constant(v)
    }

    pub fn degree(&self) -> usize {
        match self {
            Self::Constant(_) => 0,
            Self::Selector(_) | Self::Fixed(_) | Self::Advice(_) | Self::Instance(_) => 1,
            Self::Negated(p) | Self::Scaled(p, _) => p.degree(),
            Self::Sum(a, b) => core::cmp::max(a.degree(), b.degree()),
            Self::Product(a, b) => a.degree() + b.degree(),
        }
    }

    /// Debug string via `format!`. Field bytes shown BE `0x` (LE reversed).
    #[cfg(feature = "alloc")]
    pub fn to_debug_string(&self) -> String {
        match self {
            Self::Selector(s) => {
                alloc::format!("Selector(Selector({}, {}))", s.offset, s.is_simple)
            }
            Self::Fixed(q) => alloc::format!("Fixed {}", q.to_debug_string()),
            Self::Advice(q) => alloc::format!("Advice {}", q.to_debug_string()),
            Self::Instance(q) => alloc::format!("Instance {}", q.to_debug_string()),
            Self::Constant(v) => alloc::format!("Constant({})", v.to_debug_string()),
            Self::Negated(p) => alloc::format!("Negated({})", p.to_debug_string()),
            Self::Sum(a, b) => {
                alloc::format!("Sum({}, {})", a.to_debug_string(), b.to_debug_string())
            }
            Self::Product(a, b) => {
                alloc::format!("Product({}, {})", a.to_debug_string(), b.to_debug_string())
            }
            Self::Scaled(p, b) => {
                alloc::format!("Scaled({}, {})", p.to_debug_string(), b.to_debug_string())
            }
        }
    }

    pub fn contains_simple_selector(&self) -> bool {
        match self {
            Self::Selector(s) => s.is_simple,
            Self::Constant(_) | Self::Fixed(_) | Self::Advice(_) | Self::Instance(_) => false,
            Self::Negated(p) | Self::Scaled(p, _) => p.contains_simple_selector(),
            Self::Sum(a, b) | Self::Product(a, b) => {
                a.contains_simple_selector() || b.contains_simple_selector()
            }
        }
    }

    fn combine_simple(a: Option<Selector>, b: Option<Selector>) -> Halo2Result<Option<Selector>> {
        match (a, b) {
            (Some(_), Some(_)) => Err(Halo2Error::operation_failed(
                "extract_simple_selector",
                "two simple selectors in one expression",
            )),
            (Some(s), None) | (None, Some(s)) => Ok(Some(s)),
            (None, None) => Ok(None),
        }
    }

    pub fn extract_simple_selector(&self) -> Halo2Result<Option<Selector>> {
        match self {
            Self::Selector(s) => {
                if s.is_simple {
                    Ok(Some(*s))
                } else {
                    Ok(None)
                }
            }
            Self::Constant(_) | Self::Fixed(_) | Self::Advice(_) | Self::Instance(_) => Ok(None),
            Self::Negated(p) | Self::Scaled(p, _) => p.extract_simple_selector(),
            Self::Sum(a, b) | Self::Product(a, b) => {
                let x = a.extract_simple_selector()?;
                let y = b.extract_simple_selector()?;
                Self::combine_simple(x, y)
            }
        }
    }

    pub fn neg(&self) -> Expression {
        Expression::Negated(Box::new(self.clone()))
    }

    /// Addition. Rejects simple selectors via `Err`, no panic.
    pub fn try_add(&self, rhs: &Expression) -> Halo2Result<Expression> {
        if self.contains_simple_selector() || rhs.contains_simple_selector() {
            return Err(Halo2Error::operation_failed(
                "addition",
                "simple selector in addition",
            ));
        }
        Ok(Expression::Sum(
            Box::new(self.clone()),
            Box::new(rhs.clone()),
        ))
    }

    pub fn try_sub(&self, rhs: &Expression) -> Halo2Result<Expression> {
        if self.contains_simple_selector() || rhs.contains_simple_selector() {
            return Err(Halo2Error::operation_failed(
                "subtraction",
                "simple selector in subtraction",
            ));
        }
        Ok(Expression::Sum(Box::new(self.clone()), Box::new(rhs.neg())))
    }

    /// Multiply by expression. Rejects two simple-selector sides via `Err`.
    pub fn try_mul_expr(&self, rhs: &Expression) -> Halo2Result<Expression> {
        if self.contains_simple_selector() && rhs.contains_simple_selector() {
            return Err(Halo2Error::operation_failed(
                "multiplication",
                "two simple selectors",
            ));
        }
        Ok(Expression::Product(
            Box::new(self.clone()),
            Box::new(rhs.clone()),
        ))
    }

    /// Scale by field constant (Expression * Field). Always allowed.
    pub fn scale(&self, f: PallasFp) -> Expression {
        Expression::Scaled(Box::new(self.clone()), f)
    }

    pub fn square(&self) -> Halo2Result<Expression> {
        self.try_mul_expr(self)
    }

    pub fn expression_type(&self) -> ExpressionType {
        match self {
            Self::Constant(_) => ExpressionType::Constant,
            Self::Negated(_) => ExpressionType::Negated,
            Self::Sum(..) => ExpressionType::Sum,
            Self::Product(..) => ExpressionType::Product,
            Self::Scaled(..) => ExpressionType::Scaled,
            Self::Fixed(_) => ExpressionType::Fixed,
            Self::Advice(_) => ExpressionType::Advice,
            Self::Instance(_) => ExpressionType::Instance,
            Self::Selector(_) => ExpressionType::Selector,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate<T>(
        &self,
        constant: &impl Fn(PallasFp) -> T,
        selector_column: &impl Fn(Selector) -> T,
        fixed_column: &impl Fn(Query) -> T,
        advice_column: &impl Fn(Query) -> T,
        instance_column: &impl Fn(Query) -> T,
        negated: &impl Fn(T) -> T,
        sum: &impl Fn(T, T) -> T,
        product: &impl Fn(T, T) -> T,
        scaled: &impl Fn(T, PallasFp) -> T,
    ) -> T {
        match self {
            Self::Constant(v) => constant(*v),
            Self::Selector(s) => selector_column(*s),
            Self::Fixed(q) => fixed_column(*q),
            Self::Advice(q) => advice_column(*q),
            Self::Instance(q) => instance_column(*q),
            Self::Negated(p) => {
                let v = p.evaluate(
                    constant,
                    selector_column,
                    fixed_column,
                    advice_column,
                    instance_column,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                negated(v)
            }
            Self::Sum(a, b) => {
                let av = a.evaluate(
                    constant,
                    selector_column,
                    fixed_column,
                    advice_column,
                    instance_column,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                let bv = b.evaluate(
                    constant,
                    selector_column,
                    fixed_column,
                    advice_column,
                    instance_column,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                sum(av, bv)
            }
            Self::Product(a, b) => {
                let av = a.evaluate(
                    constant,
                    selector_column,
                    fixed_column,
                    advice_column,
                    instance_column,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                let bv = b.evaluate(
                    constant,
                    selector_column,
                    fixed_column,
                    advice_column,
                    instance_column,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                product(av, bv)
            }
            Self::Scaled(p, b) => {
                let av = p.evaluate(
                    constant,
                    selector_column,
                    fixed_column,
                    advice_column,
                    instance_column,
                    negated,
                    sum,
                    product,
                    scaled,
                );
                scaled(av, *b)
            }
        }
    }
}
