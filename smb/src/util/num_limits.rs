pub(crate) trait MaxVal {
    fn max_val() -> Self;
}

pub(crate) trait MinVal {
    fn min_val() -> Self;
}

pub(crate) trait One {
    fn one() -> Self;
}

pub trait Zero {
    fn zero() -> Self;
}

impl MaxVal for u8 {
    fn max_val() -> Self {
        u8::MAX
    }
}

impl MaxVal for u16 {
    fn max_val() -> Self {
        u16::MAX
    }
}

impl MaxVal for u32 {
    fn max_val() -> Self {
        u32::MAX
    }
}

impl MaxVal for u64 {
    fn max_val() -> Self {
        u64::MAX
    }
}

impl MinVal for u8 {
    fn min_val() -> Self {
        u8::MIN
    }
}

impl MinVal for u16 {
    fn min_val() -> Self {
        u16::MIN
    }
}

impl MinVal for u32 {
    fn min_val() -> Self {
        u32::MIN
    }
}

impl MinVal for u64 {
    fn min_val() -> Self {
        u64::MIN
    }
}

impl One for u8 {
    fn one() -> Self {
        1
    }
}

impl One for u16 {
    fn one() -> Self {
        1
    }
    
}

impl One for u32 {
    fn one() -> Self {
        1
    }
    
}

impl One for u64 {
    fn one() -> Self {
        1
    }

}

impl Zero for u8 {
    fn zero() -> Self {
        0
    }
}

impl Zero for u16 {
    fn zero() -> Self {
        0
    }
}

impl Zero for u32 {
    fn zero() -> Self {
        0
    }
}

impl Zero for u64 {
    fn zero() -> Self {
        0
    }
}