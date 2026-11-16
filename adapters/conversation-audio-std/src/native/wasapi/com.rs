//! Same-thread COM references. No apartment, device or pointer can be sent away.
use super::{abi, check};
use crate::Error;
use std::{ffi::c_void, marker::PhantomData, ptr::NonNull, rc::Rc};
use windows_sys::Win32::System::Com::{CoInitializeEx, CoUninitialize};
pub(super) struct Apartment(PhantomData<Rc<()>>);
impl Apartment {
    pub fn new() -> Result<Self, Error> {
        // SAFETY: null reserved pointer and the documented STA model. The
        // blocking helper's owning thread retains exactly this COM reference.
        check("CoInitializeEx(STA)", unsafe {
            CoInitializeEx(std::ptr::null(), 2)
        })?;
        Ok(Self(PhantomData))
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: non-Send guard drops on its initializing thread after all COM owners.
        unsafe { CoUninitialize() };
    }
}
pub(super) struct Object<V> {
    pointer: NonNull<c_void>,
    _type: PhantomData<(V, Rc<()>)>,
}
impl<V> Object<V> {
    /// # Safety
    /// raw is the successful original SDK result for V's exact interface IID.
    /// Its COM apartment must outlive this owner and all derived service owners.
    pub unsafe fn take(raw: *mut c_void) -> Result<Self, Error> {
        Ok(Self {
            pointer: NonNull::new(raw).ok_or(gnunet_types::Error::Malformed)?,
            _type: PhantomData,
        })
    }
    pub fn raw(&self) -> *mut c_void {
        self.pointer.as_ptr()
    }
    pub fn table(&self) -> &V {
        // SAFETY: take binds the original SDK IID to this complete vtable prefix;
        // the interface reference remains owned and used only on its apartment.
        unsafe { &**self.pointer.as_ptr().cast::<*const V>() }
    }
}
impl<V> Drop for Object<V> {
    fn drop(&mut self) {
        // SAFETY: every bound SDK interface starts with IUnknown. This owner
        // releases its one original successful reference on the same thread.
        unsafe {
            let table = &**self.pointer.as_ptr().cast::<*const abi::Unknown>();
            (table.release)(self.pointer.as_ptr());
        }
    }
}
