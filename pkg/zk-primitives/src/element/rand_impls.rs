use rand::{CryptoRng, Rng};

use crate::Element;

/// A wrapper around a randomly-generated `T` that indicates that it was not generated by a
/// cryptographically-secure hash function.
///
/// You can get access to the inner `T` by calling [`Insecure::get_insecure`], to document in code
/// that this value does need to be cryptographically secure
///
/// In particular, when used with [`Element`]:
///  - if you have a cryptographically-secure RNG, you can use [`Element::secure_random`] to
///  generate an [`Element`]
///  - if you have an insecure RNG, you can use [`Element::random`] to generate an
///  [`Insecure<Element>`]
pub struct Insecure<T> {
    inner: T,
}

impl<T> Insecure<T> {
    /// Get the potentially insecure value wrapped by this [`Insecure`]
    ///
    /// This method acts as a warning to the programmer that the value provided is not guaranteed
    /// to be generated by a cryptographically secure RNG, so should not be used in places where
    /// values must be hard-to-guess (e.g. private keys)
    pub fn get_insecure(self) -> T {
        self.inner
    }
}

impl Element {
    /// Generate a random [`Element`] using the provided [`Rng`]
    ///
    /// This function returns an [`Insecure<Element>`][Insecure], which is a thin wrapper that
    /// forces the programmer to acknowledge the potential for an attacker to guess this value.
    ///
    /// If you are using a [`CryptoRng`], consider using [`Element::secure_random`], which has this
    /// trait bound, and returns an [`Element`]
    ///
    /// ```rust,compile_fail
    /// # use zk_primitives::*;
    /// # use rand_xorshift::XorShiftRng;
    /// # use rand::SeedableRng;
    /// // this rng is NOT cryptographically secure
    /// let mut rng = XorShiftRng::from_seed([0; 16]);
    /// let element = Element::random(&mut rng);
    ///
    /// println!("{element}");  // uh oh
    /// ```
    /// To get access to the generated element, we need to call [`Insecure::get_insecure`].
    /// Hopefully this is scary enough that we will think twice where we use this value.
    /// ```rust
    /// # use zk_primitives::*;
    /// # use rand_xorshift::XorShiftRng;
    /// # use rand::SeedableRng;
    /// // this rng is NOT cryptographically secure
    /// let mut rng = XorShiftRng::from_seed([0; 16]);
    /// let element = Element::random(&mut rng);
    ///
    /// println!("{}", element.get_insecure());  // works
    /// ```
    pub fn random<R: Rng>(mut rng: R) -> Insecure<Self> {
        let mut bytes = [0; 32];
        rng.fill(&mut bytes);
        let inner = Self::from_be_bytes(bytes);
        Insecure { inner }
    }

    /// Generate a random [`Element`] using the provided cryptographically-secure [`Rng`]
    ///
    /// This function requires that the RNG implements [`CryptoRng`]. If you must use a
    /// non-cryptographically-secure RNG, consider using [`Element::random`]
    ///
    /// ```rust
    /// # use zk_primitives::*;
    /// let mut rng = rand::thread_rng();
    /// let element = Element::secure_random(&mut rng);
    ///
    /// println!("{element}");
    /// ```
    pub fn secure_random<R: Rng + CryptoRng>(mut rng: R) -> Self {
        let mut bytes = [0; 32];
        rng.fill(&mut bytes);
        Self::from_be_bytes(bytes)
    }
}
