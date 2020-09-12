extern crate ux;

use std::convert::AsMut;

pub mod error_check;
pub mod netframe;

pub fn clone_into_array<A, T>(slice: &[T]) -> A
    where
        A: Sized + Default + AsMut<[T]>,
        T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}
