#define _WIN32_WINNT 0x0500   // Windows 2000/XP
#include <windows.h>

HHOOK g_hMouseHook;
int g_screenWidth  = 0;
int g_screenHeight = 0;
BOOL g_injected    = FALSE;   // prevent recursion

LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION && wParam == WM_MOUSEMOVE) {
        PMSLLHOOKSTRUCT p = (PMSLLHOOKSTRUCT)lParam;

        if (!g_injected) {
            g_injected = TRUE;

            // Current mouse coordinates
            int x = p->pt.x;
            int y = p->pt.y;

            // Mirror horizontally around the screen center
            int centerX = g_screenWidth / 2;
            int mirroredX = 2 * centerX - x;
            int mirroredY = y;  // no vertical mirroring

            // Clamp to screen bounds
            if (mirroredX < 0) mirroredX = 0;
            if (mirroredX >= g_screenWidth) mirroredX = g_screenWidth - 1;
            if (mirroredY < 0) mirroredY = 0;
            if (mirroredY >= g_screenHeight) mirroredY = g_screenHeight - 1;

            SetCursorPos(mirroredX, mirroredY);  // move cursor [web:10]

            g_injected = FALSE;

            // Optionally swallow original movement by not calling next hook.
            // But returning non-zero here is not recommended for WM_MOUSEMOVE.
        }
    }

    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);  // chain to next hook [web:8]
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    // Get primary screen size
    g_screenWidth  = GetSystemMetrics(SM_CXSCREEN);
    g_screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // Install low-level mouse hook (global) [web:8][web:12]
    g_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc,
                                    hInstance, 0);
    if (!g_hMouseHook) {
        MessageBox(NULL, "Failed to install mouse hook", "Error", MB_ICONERROR);
        return 1;
    }

    // Standard message loop needed to keep the hook alive [web:8]
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(g_hMouseHook);
    return 0;
}

