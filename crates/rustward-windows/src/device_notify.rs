//! Configuration Manager device-change notifications
//! (`CM_Register_Notification`). **NOT VERIFIED ON WINDOWS**
//! (type-checked on other hosts with `host-typecheck`).
//!
//! TELEMETRY ONLY: notifications wake the service so it refreshes its
//! inventory promptly. They never enforce anything; a user-mode reaction
//! always races the storage stack (see `docs/ENFORCEMENT-FEASIBILITY.md`,
//! approach E).
//!
//! The subscription covers all device instances
//! (`CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES`) and forwards
//! enumerated / started / removed events to an `mpsc` channel. The
//! callback never blocks: `Sender::send` on an unbounded channel does not
//! wait, and a closed receiver is ignored.

use std::ffi::c_void;
use std::sync::mpsc::Sender;

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_NOTIFY_ACTION, CM_NOTIFY_EVENT_DATA, CM_NOTIFY_FILTER, CM_NOTIFY_FILTER_0,
    CM_NOTIFY_FILTER_0_2, CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES,
    CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE, CM_Register_Notification, CM_Unregister_Notification,
    CR_SUCCESS, HCMNOTIFICATION,
};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;

use crate::devchange::{DeviceChange, MAX_DEVICE_ID_LEN, decode_device_instance_event};

/// Registration failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("CM_Register_Notification failed with CONFIGRET {0:#x}")]
pub struct NotifyError(pub u32);

/// Live subscription; unregisters on drop (and only then frees the
/// callback context).
pub struct DeviceChangeSubscription {
    handle: HCMNOTIFICATION,
    context: *mut Sender<DeviceChange>,
}

// SAFETY: the handle is an opaque registration token usable from any
// thread, and the context is only dereferenced by the callback (which
// Configuration Manager stops calling before CM_Unregister_Notification
// returns) and freed in Drop after unregistration.
unsafe impl Send for DeviceChangeSubscription {}

impl std::fmt::Debug for DeviceChangeSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceChangeSubscription")
            .finish_non_exhaustive()
    }
}

/// Header size of `CM_NOTIFY_EVENT_DATA` before the variable-length
/// instance ID.
const EVENT_HEADER_BYTES: usize = std::mem::offset_of!(CM_NOTIFY_EVENT_DATA, u);

unsafe extern "system" fn callback(
    _notify: HCMNOTIFICATION,
    context: *const c_void,
    action: CM_NOTIFY_ACTION,
    event_data: *const CM_NOTIFY_EVENT_DATA,
    event_data_size: u32,
) -> u32 {
    if context.is_null() || event_data.is_null() {
        return ERROR_SUCCESS;
    }
    let total = usize::try_from(event_data_size).unwrap_or(0);
    let Some(payload_bytes) = total.checked_sub(EVENT_HEADER_BYTES) else {
        return ERROR_SUCCESS;
    };
    let units = (payload_bytes / 2).min(MAX_DEVICE_ID_LEN + 1);
    // SAFETY: Configuration Manager guarantees `event_data` points to
    // `event_data_size` readable bytes for the duration of the callback.
    // The instance ID starts at the union offset and `units` UTF-16 code
    // units fit inside that size (computed above). The union field is
    // `[u16; 1]`, so the pointer is suitably aligned for u16.
    let ids = unsafe {
        let first = std::ptr::addr_of!((*event_data).u.DeviceInstance.InstanceId).cast::<u16>();
        std::slice::from_raw_parts(first, units)
    };
    if let Some(change) = decode_device_instance_event(action, ids) {
        // SAFETY: `context` is the `Box<Sender>` leaked in `register`; it is
        // freed only after CM_Unregister_Notification has returned, which
        // guarantees no callback is still running.
        let sender = unsafe { &*context.cast::<Sender<DeviceChange>>() };
        let _ = sender.send(change);
    }
    ERROR_SUCCESS
}

impl DeviceChangeSubscription {
    /// Subscribe to all device-instance arrivals and removals.
    pub fn register(sender: Sender<DeviceChange>) -> Result<Self, NotifyError> {
        let context = Box::into_raw(Box::new(sender));
        let filter = CM_NOTIFY_FILTER {
            cbSize: u32::try_from(size_of::<CM_NOTIFY_FILTER>()).unwrap_or(u32::MAX),
            Flags: CM_NOTIFY_FILTER_FLAG_ALL_DEVICE_INSTANCES,
            FilterType: CM_NOTIFY_FILTER_TYPE_DEVICEINSTANCE,
            Reserved: 0,
            u: CM_NOTIFY_FILTER_0 {
                DeviceInstance: CM_NOTIFY_FILTER_0_2 {
                    InstanceId: [0; 200],
                },
            },
        };
        let mut handle: HCMNOTIFICATION = std::ptr::null_mut();
        // SAFETY: `filter` is a fully initialised CM_NOTIFY_FILTER with the
        // correct cbSize; `context` is a valid heap pointer kept alive until
        // Drop; `callback` matches PCM_NOTIFY_CALLBACK; `handle` is a valid
        // out-pointer.
        let cr = unsafe {
            CM_Register_Notification(&filter, context.cast(), Some(callback), &mut handle)
        };
        if cr != CR_SUCCESS {
            // SAFETY: registration failed, so no callback can reference
            // `context`; reclaim the box exactly once.
            drop(unsafe { Box::from_raw(context) });
            return Err(NotifyError(cr));
        }
        Ok(Self { handle, context })
    }
}

impl Drop for DeviceChangeSubscription {
    fn drop(&mut self) {
        // SAFETY: `handle` came from a successful CM_Register_Notification.
        // CM_Unregister_Notification waits for in-flight callbacks, after
        // which `context` is no longer referenced and can be freed once.
        // Drop never runs on the callback thread (the callback holds no
        // subscription), as the documentation requires.
        unsafe {
            CM_Unregister_Notification(self.handle);
            drop(Box::from_raw(self.context));
        }
    }
}
