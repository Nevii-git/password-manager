#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vault.h"

#define ID_BTN_GEN   1001
#define ID_BTN_SHOW  1002
#define ID_EDIT_ASK  2001

HINSTANCE g_hInst;
HWND g_hMainWnd;

// -------- petite fonction pour demander une chaîne (InputBox maison) --------

typedef struct {
    const char* title;
    const char* prompt;
    char* outBuf;
    size_t outSize;
    int result; // 1 = OK, 0 = Cancel
} ASK_STRING_CTX;

static LRESULT CALLBACK AskWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static ASK_STRING_CTX* ctx = NULL;
    static HWND hEdit;

    switch (msg) {
    case WM_CREATE: {
        LPCREATESTRUCT cs = (LPCREATESTRUCT)lParam;
        ctx = (ASK_STRING_CTX*)cs->lpCreateParams;

        CreateWindowA("STATIC", ctx->prompt,
            WS_VISIBLE | WS_CHILD,
            10, 10, 360, 20,
            hwnd, NULL, g_hInst, NULL);

        hEdit = CreateWindowA("EDIT", "",
            WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
            10, 40, 360, 25,
            hwnd, (HMENU)ID_EDIT_ASK, g_hInst, NULL);

        CreateWindowA("BUTTON", "OK",
            WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            110, 80, 80, 25,
            hwnd, (HMENU)IDOK, g_hInst, NULL);

        CreateWindowA("BUTTON", "Annuler",
            WS_VISIBLE | WS_CHILD,
            210, 80, 80, 25,
            hwnd, (HMENU)IDCANCEL, g_hInst, NULL);

        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK: {
            char buf[512];
            GetWindowTextA(hEdit, buf, sizeof(buf));
            strncpy_s(ctx->outBuf, ctx->outSize, buf, _TRUNCATE);
            ctx->result = 1;
            DestroyWindow(hwnd);
            return 0;
        }
        case IDCANCEL:
            ctx->result = 0;
            DestroyWindow(hwnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        ctx->result = 0;
        DestroyWindow(hwnd);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static int ask_string(HWND parent, const char* title, const char* prompt,
    char* outBuf, size_t outSize)
{
    ASK_STRING_CTX ctx;
    ctx.title = title;
    ctx.prompt = prompt;
    ctx.outBuf = outBuf;
    ctx.outSize = outSize;
    ctx.result = 0;

    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = AskWndProc;
    wc.hInstance = g_hInst;
    wc.lpszClassName = "AskStringClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClassA(&wc);

    HWND hwnd = CreateWindowA("AskStringClass", title,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 160,
        parent, NULL, g_hInst, &ctx);

    ShowWindow(hwnd, SW_SHOWNORMAL);
    UpdateWindow(hwnd);

    MSG msg;
    while (IsWindow(hwnd) && GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    UnregisterClassA("AskStringClass", g_hInst);

    return ctx.result;
}

// -------- fenêtre principale --------

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // Style 2 : deux gros boutons centrés verticalement
        RECT rc;
        GetClientRect(hwnd, &rc);

        int btnWidth = 220;
        int btnHeight = 40;
        int centerX = (rc.right - rc.left) / 2 - btnWidth / 2;

        CreateWindowA("BUTTON", "G\u00e9n\u00e9rer un mot de passe",
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            centerX, 40, btnWidth, btnHeight,
            hwnd, (HMENU)ID_BTN_GEN, g_hInst, NULL);

        CreateWindowA("BUTTON", "Afficher les mots de passe",
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            centerX, 100, btnWidth, btnHeight,
            hwnd, (HMENU)ID_BTN_SHOW, g_hInst, NULL);

        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_GEN: {
            char site[256] = { 0 };
            char id[256] = { 0 };
            char pwd[32] = { 0 };

            if (!ask_string(hwnd, "Nouveau mot de passe", "Site :", site, sizeof(site)))
                return 0;
            if (!ask_string(hwnd, "Nouveau mot de passe", "Identifiant de connexion :", id, sizeof(id)))
                return 0;

            vault_generate_password(pwd, 16);
            if (vault_add_entry(site, id, pwd) != 0) {
                MessageBoxA(hwnd, "Erreur lors de l'ajout du mot de passe au coffre.",
                    "Erreur", MB_ICONERROR);
            }
            else {
                char msgbuf[512];
                snprintf(msgbuf, sizeof(msgbuf), "Mot de passe g\u00e9n\u00e9r\u00e9 :\n\n%s", pwd);
                MessageBoxA(hwnd, msgbuf, "Mot de passe g\u00e9n\u00e9r\u00e9", MB_ICONINFORMATION);
            }
            return 0;
        }
        case ID_BTN_SHOW: {
            char* entries = vault_get_all_entries();
            if (!entries || entries[0] == '\0') {
                MessageBoxA(hwnd, "Aucun mot de passe enregistr\u00e9.",
                    "Informations", MB_ICONINFORMATION);
            }
            else {
                MessageBoxA(hwnd, entries, "Mots de passe enregistr\u00e9s", MB_OK);
            }
            if (entries) free(entries);
            return 0;
        }
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// -------- WinMain --------

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInstance;

    if (vault_sodium_init() != 0) {
        MessageBoxA(NULL, "Impossible d'initialiser libsodium.", "Erreur", MB_ICONERROR);
        return 1;
    }

    char master1[256] = { 0 };
    char master2[256] = { 0 };

    if (!vault_exists()) {
        // Premier lancement : creation du coffre
        if (!ask_string(NULL, "Mot de passe ma\u00eetre",
            "Cr\u00e9ez un mot de passe ma\u00eetre :", master1, sizeof(master1))) {
            return 0;
        }
        if (!ask_string(NULL, "Mot de passe ma\u00eetre",
            "Confirmez le mot de passe ma\u00eetre :", master2, sizeof(master2))) {
            return 0;
        }
        if (strcmp(master1, master2) != 0) {
            MessageBoxA(NULL, "Les mots de passe ne correspondent pas.", "Erreur", MB_ICONERROR);
            return 0;
        }
        if (vault_create_new(master1) != 0) {
            MessageBoxA(NULL, "Impossible de cr\u00e9er le coffre.", "Erreur", MB_ICONERROR);
            return 1;
        }
    }
    else {
        // Coffre existant : demande du mot de passe
        if (!ask_string(NULL, "Mot de passe ma\u00eetre",
            "Entrez votre mot de passe ma\u00eetre :", master1, sizeof(master1))) {
            return 0;
        }
        if (vault_open(master1) != 0) {
            MessageBoxA(NULL, "Mot de passe ma\u00eetre incorrect ou coffre corrompu.",
                "Erreur", MB_ICONERROR);
            return 1;
        }
    }

    // Fen\u00eatre principale
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "PasswordKeeperMainClass";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClassA(&wc);

    g_hMainWnd = CreateWindowA("PasswordKeeperMainClass",
        "Gestionnaire de mots de passe",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        500, 220,
        NULL, NULL, hInstance, NULL);

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    vault_cleanup();
    return (int)msg.wParam;
}
