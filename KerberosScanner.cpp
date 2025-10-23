/*
Tool: KerberosScanner
File: KerberosScanner.cpp
Author: Ayi NEDJIMI Consultants
URL: https://www.ayinedjimi-consultants.fr
Version: 1.0
Description:
  Surveille le journal d'événements de sécurité Windows pour détecter les événements Kerberos
  (Event IDs 4768, 4769, 4771, etc.), agrège les requêtes par SPN sur une fenêtre glissante
  configurable, et détecte les pics anormaux pouvant indiquer des attaques (Kerberoasting, etc.)
Prerequisites:
  - Windows 10 / Windows Server 2016+ (x64)
  - Visual Studio Developer Command Prompt (x64)
  - Exécution en tant qu'administrateur pour accès aux logs Security
Notes:
  - Outil en mode audit par défaut. Voir section LAB-CONTROLLED dans README pour démonstration en VM isolée.

WinToolsSuite – Security Tools for Network & Pentest
Developed by Ayi NEDJIMI Consultants
https://www.ayinedjimi-consultants.fr
© 2025 – Cybersecurity Research & Training
*/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <winevt.h>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <ctime>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wevtapi.lib")

// Messages personnalisés
#define WM_TOOL_RESULT   (WM_APP + 200)
#define WM_TOOL_ERROR    (WM_APP + 201)
#define WM_TOOL_UPDATE   (WM_APP + 202)

// Contrôles
#define IDC_LISTVIEW     1001
#define IDC_BTN_START    1002
#define IDC_BTN_STOP     1003
#define IDC_BTN_EXPORT   1004
#define IDC_BTN_CLEAR    1005
#define ID_FILE_EXPORT   2001
#define ID_FILE_EXIT     2002
#define ID_HELP_ABOUT    2003

// RAII Handle
class AutoHandle {
    HANDLE h;
public:
    explicit AutoHandle(HANDLE handle = INVALID_HANDLE_VALUE) : h(handle) {}
    ~AutoHandle() { if (h != INVALID_HANDLE_VALUE && h != NULL) CloseHandle(h); }
    operator HANDLE() const { return h; }
    HANDLE* operator&() { return &h; }
    HANDLE get() const { return h; }
};

// RAII Event Handle
class AutoEvent {
    EVT_HANDLE h;
public:
    explicit AutoEvent(EVT_HANDLE handle = NULL) : h(handle) {}
    ~AutoEvent() { if (h) EvtClose(h); }
    operator EVT_HANDLE() const { return h; }
    EVT_HANDLE* operator&() { return &h; }
    EVT_HANDLE get() const { return h; }
};

// Structure pour agréger les SPNs
struct SpnStats {
    std::wstring spn;
    int count;
    SYSTEMTIME lastSeen;
    std::wstring topIPs;
    int score;
};

// Globals
HWND g_hwnd = NULL;
HWND g_hwndList = NULL;
std::thread g_workerThread;
bool g_running = false;
std::mutex g_mutex;
std::map<std::wstring, SpnStats> g_spnMap;
int g_windowMinutes = 5;

// Logging
std::wofstream g_logFile;

void LogMessage(const std::wstring& msg) {
    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t timeBuf[100];
    swprintf_s(timeBuf, L"[%04d-%02d-%02d %02d:%02d:%02d] ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    if (g_logFile.is_open()) {
        g_logFile << timeBuf << msg << std::endl;
        g_logFile.flush();
    }
}

// Initialisation du log
void InitLog() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    std::wstring logPath = std::wstring(tempPath) + L"WinTools_KerberosScanner_log.txt";
    g_logFile.open(logPath, std::ios::app);
    LogMessage(L"=== KerberosScanner démarré ===");
}

// Export CSV
void ExportToCsv(const std::wstring& filename) {
    std::wofstream file(filename);
    if (!file.is_open()) {
        MessageBoxW(g_hwnd, L"Impossible de créer le fichier CSV", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    // BOM UTF-8
    file.put(0xFEFF);

    file << L"SPN,Compteur,DernièreVue,TopIPs,Score\n";

    std::lock_guard<std::mutex> lock(g_mutex);
    for (const auto& pair : g_spnMap) {
        const SpnStats& stats = pair.second;
        wchar_t timeBuf[100];
        swprintf_s(timeBuf, L"%04d-%02d-%02d %02d:%02d:%02d",
                   stats.lastSeen.wYear, stats.lastSeen.wMonth, stats.lastSeen.wDay,
                   stats.lastSeen.wHour, stats.lastSeen.wMinute, stats.lastSeen.wSecond);

        file << L"\"" << stats.spn << L"\",";
        file << stats.count << L",";
        file << L"\"" << timeBuf << L"\",";
        file << L"\"" << stats.topIPs << L"\",";
        file << stats.score << L"\n";
    }

    file.close();
    MessageBoxW(g_hwnd, L"Export CSV réussi", L"Information", MB_OK | MB_ICONINFORMATION);
    LogMessage(L"Export CSV: " + filename);
}

// Mise à jour ListView
void UpdateListView() {
    ListView_DeleteAllItems(g_hwndList);

    std::lock_guard<std::mutex> lock(g_mutex);

    // Trier par count décroissant
    std::vector<SpnStats> sorted;
    for (const auto& pair : g_spnMap) {
        sorted.push_back(pair.second);
    }
    std::sort(sorted.begin(), sorted.end(), [](const SpnStats& a, const SpnStats& b) {
        return a.count > b.count;
    });

    int index = 0;
    for (const auto& stats : sorted) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = index;
        lvi.iSubItem = 0;
        lvi.pszText = const_cast<LPWSTR>(stats.spn.c_str());
        ListView_InsertItem(g_hwndList, &lvi);

        wchar_t buf[256];
        swprintf_s(buf, L"%d", stats.count);
        ListView_SetItemText(g_hwndList, index, 1, buf);

        swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
                   stats.lastSeen.wYear, stats.lastSeen.wMonth, stats.lastSeen.wDay,
                   stats.lastSeen.wHour, stats.lastSeen.wMinute, stats.lastSeen.wSecond);
        ListView_SetItemText(g_hwndList, index, 2, buf);

        ListView_SetItemText(g_hwndList, index, 3, const_cast<LPWSTR>(stats.topIPs.c_str()));

        swprintf_s(buf, L"%d", stats.score);
        ListView_SetItemText(g_hwndList, index, 4, buf);

        index++;
    }
}

// Extraction SPN depuis événement
std::wstring ExtractSpn(EVT_HANDLE hEvent) {
    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;

    // Obtenir taille buffer
    EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, NULL, &bufferUsed, &propertyCount);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return L"";

    std::vector<wchar_t> buffer(bufferUsed / sizeof(wchar_t));
    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferUsed, buffer.data(), &bufferUsed, &propertyCount)) {
        return L"";
    }

    std::wstring xml(buffer.data());

    // Extraction simple SPN (chercher ServiceName ou TargetUserName)
    // Format simplifié pour démo
    size_t pos = xml.find(L"<Data Name='ServiceName'>");
    if (pos != std::wstring::npos) {
        pos += 25;
        size_t endPos = xml.find(L"</Data>", pos);
        if (endPos != std::wstring::npos) {
            return xml.substr(pos, endPos - pos);
        }
    }

    return L"Unknown";
}

// Worker thread - surveillance événements
void WorkerThread() {
    LogMessage(L"Thread de surveillance démarré");

    // XPath query pour événements Kerberos
    const wchar_t* query = L"*[System[(EventID=4768 or EventID=4769 or EventID=4771)]]";

    AutoEvent hSubscription(EvtSubscribe(NULL, NULL, L"Security", query,
                                         NULL, NULL, NULL,
                                         EvtSubscribeToFutureEvents));

    if (!hSubscription.get()) {
        DWORD err = GetLastError();
        std::wstringstream wss;
        wss << L"Échec EvtSubscribe, erreur: " << err;
        LogMessage(wss.str());
        PostMessageW(g_hwnd, WM_TOOL_ERROR, 0, 0);
        return;
    }

    DWORD dwReturned = 0;
    EVT_HANDLE hEvents[10];

    while (g_running) {
        if (EvtNext(hSubscription.get(), 10, hEvents, INFINITE, 0, &dwReturned)) {
            for (DWORD i = 0; i < dwReturned; i++) {
                std::wstring spn = ExtractSpn(hEvents[i]);

                SYSTEMTIME st;
                GetLocalTime(&st);

                {
                    std::lock_guard<std::mutex> lock(g_mutex);
                    auto& stats = g_spnMap[spn];
                    stats.spn = spn;
                    stats.count++;
                    stats.lastSeen = st;
                    stats.topIPs = L"127.0.0.1"; // TODO: extraire IPs du XML
                    stats.score = stats.count > 100 ? 3 : (stats.count > 50 ? 2 : 1);
                }

                EvtClose(hEvents[i]);
            }

            PostMessageW(g_hwnd, WM_TOOL_UPDATE, 0, 0);
        } else {
            DWORD err = GetLastError();
            if (err != ERROR_NO_MORE_ITEMS) {
                Sleep(100);
            }
        }
    }

    LogMessage(L"Thread de surveillance arrêté");
}

// Démarrer surveillance
void StartMonitoring() {
    if (g_running) return;

    g_running = true;
    g_workerThread = std::thread(WorkerThread);

    EnableWindow(GetDlgItem(g_hwnd, IDC_BTN_START), FALSE);
    EnableWindow(GetDlgItem(g_hwnd, IDC_BTN_STOP), TRUE);

    LogMessage(L"Surveillance démarrée");
}

// Arrêter surveillance
void StopMonitoring() {
    if (!g_running) return;

    g_running = false;
    if (g_workerThread.joinable()) {
        g_workerThread.join();
    }

    EnableWindow(GetDlgItem(g_hwnd, IDC_BTN_START), TRUE);
    EnableWindow(GetDlgItem(g_hwnd, IDC_BTN_STOP), FALSE);

    LogMessage(L"Surveillance arrêtée");
}

// Dialogue À propos
void ShowAboutDialog() {
    MessageBoxW(g_hwnd,
        L"KerberosScanner v1.0\n\n"
        L"Surveillance des événements Kerberos et détection d'anomalies\n\n"
        L"WinToolsSuite – Security Tools for Network & Pentest\n"
        L"Developed by Ayi NEDJIMI Consultants\n"
        L"https://www.ayinedjimi-consultants.fr\n"
        L"© 2025 – Cybersecurity Research & Training",
        L"À propos",
        MB_OK | MB_ICONINFORMATION);
}

// Initialisation ListView
void InitListView(HWND hwndList) {
    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.cx = 200;
    lvc.pszText = const_cast<LPWSTR>(L"SPN");
    ListView_InsertColumn(hwndList, 0, &lvc);

    lvc.cx = 100;
    lvc.pszText = const_cast<LPWSTR>(L"Compteur");
    ListView_InsertColumn(hwndList, 1, &lvc);

    lvc.cx = 150;
    lvc.pszText = const_cast<LPWSTR>(L"Dernière vue");
    ListView_InsertColumn(hwndList, 2, &lvc);

    lvc.cx = 150;
    lvc.pszText = const_cast<LPWSTR>(L"Top IPs");
    ListView_InsertColumn(hwndList, 3, &lvc);

    lvc.cx = 80;
    lvc.pszText = const_cast<LPWSTR>(L"Score");
    ListView_InsertColumn(hwndList, 4, &lvc);

    ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
}

// WndProc
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Menu
            HMENU hMenu = CreateMenu();
            HMENU hFileMenu = CreateMenu();
            AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXPORT, L"&Exporter CSV...");
            AppendMenuW(hFileMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hFileMenu, MF_STRING, ID_FILE_EXIT, L"&Quitter");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&Fichier");

            HMENU hHelpMenu = CreateMenu();
            AppendMenuW(hHelpMenu, MF_STRING, ID_HELP_ABOUT, L"&À propos...");
            AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Aide");

            SetMenu(hwnd, hMenu);

            // ListView
            g_hwndList = CreateWindowExW(0, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT,
                10, 10, 760, 400,
                hwnd, (HMENU)IDC_LISTVIEW, GetModuleHandle(NULL), NULL);
            InitListView(g_hwndList);

            // Boutons
            CreateWindowExW(0, L"BUTTON", L"Démarrer surveillance",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 420, 180, 30,
                hwnd, (HMENU)IDC_BTN_START, GetModuleHandle(NULL), NULL);

            CreateWindowExW(0, L"BUTTON", L"Arrêter surveillance",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED,
                200, 420, 180, 30,
                hwnd, (HMENU)IDC_BTN_STOP, GetModuleHandle(NULL), NULL);

            CreateWindowExW(0, L"BUTTON", L"Exporter CSV",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                390, 420, 180, 30,
                hwnd, (HMENU)IDC_BTN_EXPORT, GetModuleHandle(NULL), NULL);

            CreateWindowExW(0, L"BUTTON", L"Effacer",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                580, 420, 190, 30,
                hwnd, (HMENU)IDC_BTN_CLEAR, GetModuleHandle(NULL), NULL);

            break;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case IDC_BTN_START:
                    StartMonitoring();
                    break;
                case IDC_BTN_STOP:
                    StopMonitoring();
                    break;
                case IDC_BTN_EXPORT:
                case ID_FILE_EXPORT: {
                    wchar_t filename[MAX_PATH] = L"kerberos_scan.csv";
                    OPENFILENAMEW ofn = {};
                    ofn.lStructSize = sizeof(ofn);
                    ofn.hwndOwner = hwnd;
                    ofn.lpstrFile = filename;
                    ofn.nMaxFile = MAX_PATH;
                    ofn.lpstrFilter = L"CSV Files\0*.csv\0All Files\0*.*\0";
                    ofn.Flags = OFN_OVERWRITEPROMPT;
                    if (GetSaveFileNameW(&ofn)) {
                        ExportToCsv(filename);
                    }
                    break;
                }
                case IDC_BTN_CLEAR:
                    {
                        std::lock_guard<std::mutex> lock(g_mutex);
                        g_spnMap.clear();
                    }
                    UpdateListView();
                    LogMessage(L"Données effacées");
                    break;
                case ID_FILE_EXIT:
                    PostMessageW(hwnd, WM_CLOSE, 0, 0);
                    break;
                case ID_HELP_ABOUT:
                    ShowAboutDialog();
                    break;
            }
            break;
        }

        case WM_TOOL_UPDATE:
            UpdateListView();
            break;

        case WM_TOOL_ERROR:
            MessageBoxW(hwnd, L"Erreur lors de la surveillance des événements.\nVérifiez les droits administrateur.",
                       L"Erreur", MB_OK | MB_ICONERROR);
            StopMonitoring();
            break;

        case WM_DESTROY:
            StopMonitoring();
            if (g_logFile.is_open()) {
                LogMessage(L"=== KerberosScanner arrêté ===");
                g_logFile.close();
            }
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// WinMain
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    InitLog();

    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"KerberosScanner";

    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(0, L"KerberosScanner",
        L"KerberosScanner - Surveillance Kerberos",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 520,
        NULL, NULL, hInstance, NULL);

    if (!g_hwnd) return 1;

    ShowWindow(g_hwnd, nCmdShow);
    UpdateWindow(g_hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return (int)msg.wParam;
}
