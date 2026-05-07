/// do_something().map_err(|_| anyhow!("error_msg")) breaks hax.
///
pub trait HaxHelper<T, E> {
    fn ok_or_err(self, msg: &'static str) -> Result<T, anyhow::Error>;
    fn err(self, msg: &'static str) -> anyhow::Error;
}

impl<T, E> HaxHelper<T, E> for Result<T, E> {
    fn ok_or_err(self, msg: &'static str) -> Result<T, anyhow::Error> {
        match self {
            Ok(v) => Ok(v),
            Err(_) => Err(anyhow::anyhow!(msg)),
        }
    }

    fn err(self, msg: &'static str) -> anyhow::Error {
        anyhow::anyhow!(msg)
    }
}
