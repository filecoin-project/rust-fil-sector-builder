#[derive(Default)]
pub(crate) struct Deallocator {
    pub destructors: Vec<Box<dyn Fn()>>,
}

impl Drop for Deallocator {
    fn drop(&mut self) {
        for f in self.destructors.iter() {
            f();
        }
    }
}
