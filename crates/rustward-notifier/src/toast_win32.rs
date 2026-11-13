//! Native Windows desktop notification presenter using the Shell Notification Icon
//! Action Center API (`Shell_NotifyIconW`), completely outside Session 0.

#[cfg(not(windows))]
use crate::poller::{ToastMessage, ToastPresenter};

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::ptr;

    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::{
        NIF_ICON, NIF_INFO, NIF_REALTIME, NIF_TIP, NIIF_INFO, NIIF_RESPECT_QUIET_TIME,
        NIIF_WARNING, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NOTIFYICONDATAW,
        NOTIFYICON_VERSION_4, SetCurrentProcessExplicitAppUserModelID, Shell_NotifyIconW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, IDI_APPLICATION,
        IDI_SHIELD, LoadIconW, MSG, PM_REMOVE, PeekMessageW, PostQuitMessage, RegisterClassW,
        TranslateMessage, WM_DESTROY, WM_ENDSESSION, WM_QUERYENDSESSION, WNDCLASSW,
    };

    use crate::poller::{ToastMessage, ToastPresenter};

    const APP_USER_MODEL_ID: &str = "Terabithia.RustWard.Desktop";
    const TRAY_ICON_ID: u32 = 1;

    fn wide_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn copy_wide<const N: usize>(dest: &mut [u16; N], s: &str) {
        dest.fill(0);
        for (idx, ch) in s.encode_utf16().enumerate() {
            if idx + 1 >= N {
                break;
            }
            dest[idx] = ch;
        }
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_QUERYENDSESSION => 1,
            WM_ENDSESSION => {
                if wparam != 0 {
                    // SAFETY: Called on the window thread when the user session is ending.
                    unsafe { PostQuitMessage(0) };
                }
                0
            }
            WM_DESTROY => {
                // SAFETY: Standard Win32 destroy handler.
                unsafe { PostQuitMessage(0) };
                0
            }
            // SAFETY: Default window procedure for unhandled messages.
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    /// Win32 taskbar + Windows Action Center toast presenter for the current user session.
    pub struct Win32ToastPresenter {
        hwnd: HWND,
        icon_added: bool,
        should_quit: bool,
    }

    impl Win32ToastPresenter {
        /// Create the hidden top-level notification owner window and add the tray icon.
        pub fn create() -> Result<Self, String> {
            let aumid = wide_nul(APP_USER_MODEL_ID);
            // SAFETY: Valid NUL-terminated UTF-16 AUMID string; return value is best effort.
            unsafe {
                let _ = SetCurrentProcessExplicitAppUserModelID(aumid.as_ptr());
            }

            // SAFETY: Null returns the module handle for the current executable.
            let hinstance = unsafe { GetModuleHandleW(ptr::null()) };
            let class_name = wide_nul("RustWardNotifierHiddenWindow");
            let window_title = wide_nul("RustWard Bildirim Ajanı");

            // SAFETY: POD Win32 WNDCLASSW zero-initialization.
            let mut wc: WNDCLASSW = unsafe { core::mem::zeroed() };
            wc.lpfnWndProc = Some(wnd_proc);
            wc.hInstance = hinstance;
            wc.lpszClassName = class_name.as_ptr();
            // SAFETY: Valid WNDCLASSW with `'static` function pointer and valid UTF-16 class name.
            unsafe {
                let _ = RegisterClassW(&wc);
            }

            // SAFETY: Top-level unshown WS_OVERLAPPED window (not HWND_MESSAGE) so Shell
            // notifications integrate cleanly with Windows Action Center and session shutdown.
            let hwnd = unsafe {
                CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    window_title.as_ptr(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    hinstance,
                    ptr::null::<c_void>(),
                )
            };
            if hwnd.is_null() {
                return Err("CreateWindowExW for notifier failed".into());
            }

            let mut presenter = Self {
                hwnd,
                icon_added: false,
                should_quit: false,
            };
            presenter.ensure_tray_icon();
            Ok(presenter)
        }

        fn ensure_tray_icon(&mut self) {
            if self.icon_added {
                return;
            }
            // SAFETY: Standard system icon identifiers with null module handle.
            let mut hicon = unsafe { LoadIconW(ptr::null_mut(), IDI_SHIELD) };
            if hicon.is_null() {
                // SAFETY: Fallback built-in icon if IDI_SHIELD is unavailable.
                hicon = unsafe { LoadIconW(ptr::null_mut(), IDI_APPLICATION) };
            }
            // SAFETY: POD Win32 NOTIFYICONDATAW zero-initialization.
            let mut nid: NOTIFYICONDATAW = unsafe { core::mem::zeroed() };
            nid.cbSize = core::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = self.hwnd;
            nid.uID = TRAY_ICON_ID;
            nid.uFlags = NIF_ICON | NIF_TIP;
            nid.hIcon = hicon;
            copy_wide(&mut nid.szTip, "RustWard — USB Güvenlik Monitörü");
            // SAFETY: Valid NOTIFYICONDATAW pointing to our owned hidden window.
            let added = unsafe { Shell_NotifyIconW(NIM_ADD, &nid) };
            if added != 0 {
                nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
                // SAFETY: Setting version on an existing tray icon owned by `self.hwnd`.
                unsafe {
                    let _ = Shell_NotifyIconW(NIM_SETVERSION, &nid);
                }
                self.icon_added = true;
            }
        }

        /// Process any queued Win32 messages (including `WM_ENDSESSION` on user sign-out).
        pub fn pump_messages(&mut self) -> bool {
            // SAFETY: POD Win32 MSG zero-initialization.
            let mut msg: MSG = unsafe { core::mem::zeroed() };
            // SAFETY: Non-blocking PeekMessageW loop on the owning thread's message queue.
            while unsafe { PeekMessageW(&mut msg, ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
                if msg.message == windows_sys::Win32::UI::WindowsAndMessaging::WM_QUIT {
                    self.should_quit = true;
                }
                // SAFETY: Dispatching the retrieved Win32 message.
                unsafe {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            !self.should_quit
        }
    }

    impl ToastPresenter for Win32ToastPresenter {
        fn show_toast(&mut self, toast: &ToastMessage) -> Result<(), String> {
            self.ensure_tray_icon();
            // SAFETY: POD Win32 NOTIFYICONDATAW zero-initialization.
            let mut nid: NOTIFYICONDATAW = unsafe { core::mem::zeroed() };
            nid.cbSize = core::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = self.hwnd;
            nid.uID = TRAY_ICON_ID;
            nid.uFlags = NIF_INFO | NIF_REALTIME | NIF_TIP;
            nid.dwInfoFlags = if toast.is_warning {
                NIIF_WARNING | NIIF_RESPECT_QUIET_TIME
            } else {
                NIIF_INFO | NIIF_RESPECT_QUIET_TIME
            };
            copy_wide(&mut nid.szTip, "RustWard — USB Güvenlik Monitörü");
            copy_wide(&mut nid.szInfoTitle, &toast.title);
            copy_wide(&mut nid.szInfo, &toast.body);

            let cmd = if self.icon_added { NIM_MODIFY } else { NIM_ADD };
            // SAFETY: Valid NOTIFYICONDATAW for `self.hwnd`.
            let ok = unsafe { Shell_NotifyIconW(cmd, &nid) };
            if ok == 0 {
                return Err("Shell_NotifyIconW failed to display desktop notification".into());
            }
            self.icon_added = true;
            self.pump_messages();
            Ok(())
        }
    }

    impl Drop for Win32ToastPresenter {
        fn drop(&mut self) {
            if self.icon_added {
                // SAFETY: POD Win32 NOTIFYICONDATAW zero-initialization.
                let mut nid: NOTIFYICONDATAW = unsafe { core::mem::zeroed() };
                nid.cbSize = core::mem::size_of::<NOTIFYICONDATAW>() as u32;
                nid.hWnd = self.hwnd;
                nid.uID = TRAY_ICON_ID;
                // SAFETY: Removing the tray icon owned by `self.hwnd`.
                unsafe {
                    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
                }
            }
            if !self.hwnd.is_null() {
                // SAFETY: Destroying the hidden window owned by this presenter.
                unsafe {
                    let _ = DestroyWindow(self.hwnd);
                }
            }
        }
    }
}

#[cfg(windows)]
pub use imp::Win32ToastPresenter;

/// Non-Windows stub used when type-checking cross-platform.
#[cfg(not(windows))]
pub struct Win32ToastPresenter;

#[cfg(not(windows))]
impl Win32ToastPresenter {
    pub fn create() -> Result<Self, String> {
        Ok(Self)
    }

    pub fn pump_messages(&mut self) -> bool {
        false
    }
}

#[cfg(not(windows))]
impl ToastPresenter for Win32ToastPresenter {
    fn show_toast(&mut self, _toast: &ToastMessage) -> Result<(), String> {
        Err("desktop toast notifications require Windows".into())
    }
}
