//! Native discovery, capture and endpoint closure filters in the original session.
use super::{
    catalog::{conditions, wide},
    engine::{Engine, check},
    error::{Datagram, Error, Problem},
};
use crate::{ids, sdk};
use core::{num::NonZeroU64, ptr};

pub(super) struct Rule {
    family: Datagram,
    kind: Kind,
    callout: sdk::GUID,
    layer: sdk::GUID,
}

enum Kind {
    Discover,
    Capture,
    Closure,
}

pub(super) fn rules() -> [Rule; 6] {
    // SAFETY: native SDK layer GUID symbols are immutable.
    unsafe {
        [
            Rule {
                family: Datagram::V4,
                kind: Kind::Discover,
                callout: ids::FLOW_V4,
                layer: sdk::FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
            },
            Rule {
                family: Datagram::V6,
                kind: Kind::Discover,
                callout: ids::FLOW_V6,
                layer: sdk::FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
            },
            Rule {
                family: Datagram::V4,
                kind: Kind::Capture,
                callout: ids::DATAGRAM_V4,
                layer: sdk::FWPM_LAYER_DATAGRAM_DATA_V4,
            },
            Rule {
                family: Datagram::V6,
                kind: Kind::Capture,
                callout: ids::DATAGRAM_V6,
                layer: sdk::FWPM_LAYER_DATAGRAM_DATA_V6,
            },
            Rule {
                family: Datagram::V4,
                kind: Kind::Closure,
                callout: ids::CLOSURE_V4,
                layer: sdk::FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,
            },
            Rule {
                family: Datagram::V6,
                kind: Kind::Closure,
                callout: ids::CLOSURE_V6,
                layer: sdk::FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
            },
        ]
    }
}

const DISCOVERY_NAME: &[u16] = &wide(b"GNUnet DNS outbound flow discovery\0");
const CAPTURE_NAME: &[u16] = &wide(b"GNUnet DNS outbound capture\0");
const CLOSURE_NAME: &[u16] = &wide(b"GNUnet DNS UDP endpoint closure\0");

impl Engine {
    pub(super) fn add_capture(&self, rule: &Rule) -> Result<NonZeroU64, Error> {
        self.observe_callout(rule.family, &rule.callout, rule.layer)?;
        let [protocol, direction] = conditions(sdk::FWP_DIRECTION__FWP_DIRECTION_OUTBOUND);
        // SAFETY: these SDK input types admit zero discriminants and pointer fields.
        let mut remote = unsafe { core::mem::zeroed::<sdk::FWPM_FILTER_CONDITION0>() };
        // SAFETY: this immutable SDK GUID is the native remote port condition.
        remote.fieldKey = unsafe { sdk::FWPM_CONDITION_IP_REMOTE_PORT };
        remote.matchType = sdk::FWP_MATCH_TYPE__FWP_MATCH_EQUAL;
        remote.conditionValue.type_ = sdk::FWP_DATA_TYPE__FWP_UINT16;
        remote.conditionValue.__bindgen_anon_1.uint16 = 53;
        let mut conditions = [protocol, direction, remote];
        let mut provider = ids::GUARD_PROVIDER;
        // SAFETY: zero selects an automatic key, empty weight and null optional fields.
        let mut filter = unsafe { core::mem::zeroed::<sdk::FWPM_FILTER0>() };
        filter.displayData.name = match rule.kind {
            Kind::Discover => DISCOVERY_NAME,
            Kind::Capture => CAPTURE_NAME,
            Kind::Closure => CLOSURE_NAME,
        }
        .as_ptr()
        .cast_mut();
        filter.providerKey = &mut provider;
        filter.layerKey = rule.layer;
        filter.subLayerKey = ids::GUARD_SUBLAYER;
        // An unconnected UDP endpoint can have many remote flows. ALE closure
        // covers the endpoint irrespective of any individual remote port.
        filter.numFilterConditions = match rule.kind {
            Kind::Closure => 1,
            Kind::Discover | Kind::Capture => 3,
        };
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action.type_ = match rule.kind {
            Kind::Discover | Kind::Closure => sdk::FWP_ACTION_CALLOUT_INSPECTION,
            Kind::Capture => sdk::FWP_ACTION_CALLOUT_UNKNOWN,
        };
        filter.action.__bindgen_anon_1.calloutKey = rule.callout;
        let mut id = 0;
        // SAFETY: the active transaction borrows the bounded original fields.
        check("FwpmFilterAdd0", unsafe {
            sdk::FwpmFilterAdd0(self.raw(), &filter, ptr::null_mut(), &mut id)
        })?;
        NonZeroU64::new(id).ok_or(Error::Catalog {
            datagram: rule.family,
            problem: Problem::MissingOutput,
        })
    }
}
