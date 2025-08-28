use anyhow::Error;

/// Common client functionality for source and journalist clients
pub trait Client {
    /// Associated type for the newsroom key
    type NewsroomKey;

    /// Get the newsroom's verifying key (optional access)
    fn newsroom_verifying_key(&self) -> Option<&Self::NewsroomKey>;

    /// Store the newsroom's verifying key
    fn set_newsroom_verifying_key(&mut self, key: Self::NewsroomKey);

    /// Get the newsroom's verifying key, returning an error if not available
    fn get_newsroom_verifying_key(&self) -> Result<&Self::NewsroomKey, Error> {
        self.newsroom_verifying_key()
            .ok_or_else(|| anyhow::anyhow!("Newsroom verifying key not available"))
    }
}
