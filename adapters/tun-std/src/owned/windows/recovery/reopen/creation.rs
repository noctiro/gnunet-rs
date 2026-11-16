//! One retained provisional creator across native creation/start refusals.
use super::{Adapter, WintunReopen, WintunReopenStage, WintunReplacementKind};
use std::io;
use tokio::time::Instant;

impl WintunReopen {
    pub(super) fn retain_created(&mut self, adapter: Adapter, kind: WintunReplacementKind) {
        if kind == WintunReplacementKind::Created {
            self.provisional = Some(adapter);
        }
    }
    pub(super) fn prepare_adapter(
        &mut self,
        until: Instant,
        recreate: bool,
        stage: &mut WintunReopenStage,
    ) -> io::Result<(Adapter, WintunReplacementKind)> {
        let result = if let Some(adapter) = self.provisional.take() {
            *stage = WintunReopenStage::Create;
            let Some(recipe) = &self.recreation else {
                self.provisional = Some(adapter);
                return Err(io::Error::other(
                    "provisional creator has no original recipe",
                ));
            };
            recipe.finish(adapter, until.into_std())
        } else {
            *stage = WintunReopenStage::Open;
            match self.driver.reopen(&self.selector) {
                Ok(adapter) => return Ok((adapter, WintunReplacementKind::Reopened)),
                Err(error) if recreate && gnunet_native::wintun::is_adapter_missing(&error) => {
                    let Some(recipe) = &self.recreation else {
                        return Err(error);
                    };
                    *stage = WintunReopenStage::Create;
                    let scope = self
                        .retirement
                        .as_ref()
                        .ok_or_else(|| io::Error::other("missing recreation retirement"))?;
                    recipe.create(scope.scope(), until.into_std())
                }
                Err(error) => return Err(error),
            }
        };
        match result {
            Ok(adapter) => Ok((adapter, WintunReplacementKind::Created)),
            Err(failure) => {
                let (adapter, error) = failure.into_parts();
                self.provisional = adapter;
                Err(error)
            }
        }
    }
}
