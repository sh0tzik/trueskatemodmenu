// TrueSkateMenu - ImGui overlay for True Skate (com.trueaxis.skate), rootless / Dopamine.
// Overlay = separate UIWindow with a transparent MTKView, so we don't touch the game's renderer.

#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#include <cxxabi.h>
#include <substrate.h>
#include <string>
#include <vector>
#include <cstring>
#include <cmath>
#include <cfloat>

#include "imgui.h"
#include "imgui_impl_metal.h"

// ---------------------------------------------------------------------------
// Math / 3D Geometry primitives
// ---------------------------------------------------------------------------

namespace TA {
    struct Vec2 { float x, y; };

    struct Vec3 {
        float x, y, z;
        Vec3() : x(0.0f), y(0.0f), z(0.0f) {}
        Vec3(float _x, float _y, float _z) : x(_x), y(_y), z(_z) {}
        Vec3 operator+(const Vec3 &o) const { return Vec3(x + o.x, y + o.y, z + o.z); }
        Vec3 operator-(const Vec3 &o) const { return Vec3(x - o.x, y - o.y, z - o.z); }
        Vec3 operator*(float s) const { return Vec3(x * s, y * s, z * s); }
        Vec3 operator/(float s) const { return Vec3(x / s, y / s, z / s); }
        float Length() const { return sqrtf(x * x + y * y + z * z); }
        Vec3 Normalized() const {
            float l = Length();
            return l > 0.00001f ? (*this) * (1.0f / l) : Vec3(0, 0, 0);
        }
        static float Dot(const Vec3 &a, const Vec3 &b) {
            return a.x * b.x + a.y * b.y + a.z * b.z;
        }
        static Vec3 Cross(const Vec3 &a, const Vec3 &b) {
            return Vec3(
                a.y * b.z - a.z * b.y,
                a.z * b.x - a.x * b.z,
                a.x * b.y - a.y * b.x
            );
        }
    };
}

// ---------------------------------------------------------------------------
// Symbol resolver: the game binary keeps its symbol table, so we can find
// functions by (mangled) name at runtime instead of hardcoding offsets.
// Offsets survive game updates this way.
// ---------------------------------------------------------------------------

struct SymHit {
    std::string mangled;    // as stored in symtab (with leading underscore)
    std::string pretty;     // demangled
    uint64_t    vmaddr;     // address as shown in Ghidra/IDA (unslid)
};

template <typename Fn>
static void ForEachSymbol(Fn fn) {
    const struct mach_header_64 *mh = nullptr;
    intptr_t slide = 0;
    uint32_t imgN = _dyld_image_count();
    for (uint32_t i = 0; i < imgN; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (h && h->filetype == MH_EXECUTE) {   // the game binary, not an injected lib
            mh = h; slide = _dyld_get_image_vmaddr_slide(i); break;
        }
    }
    if (!mh) return;

    const struct symtab_command *symtab = nullptr;
    const struct segment_command_64 *linkedit = nullptr;
    const uint8_t *p = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SYMTAB) symtab = (const struct symtab_command *)lc;
        else if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *s = (const struct segment_command_64 *)lc;
            if (!strcmp(s->segname, "__LINKEDIT")) linkedit = s;
        }
        p += lc->cmdsize;
    }
    if (!symtab || !linkedit) return;

    uintptr_t base = (uintptr_t)linkedit->vmaddr + slide - linkedit->fileoff;
    const struct nlist_64 *syms = (const struct nlist_64 *)(base + symtab->symoff);
    const char *strs = (const char *)(base + symtab->stroff);
    for (uint32_t i = 0; i < symtab->nsyms; i++) {
        if ((syms[i].n_type & N_TYPE) != N_SECT) continue;
        if (!syms[i].n_un.n_strx) continue;
        fn(strs + syms[i].n_un.n_strx, (uint64_t)syms[i].n_value, slide);
    }
}

// name must include the leading underscore, e.g. "__ZN4Game32OverridePhysicsSettingsFromStatsEv"
static void *FindSymbol(const char *name) {
    void *found = nullptr;
    ForEachSymbol([&](const char *n, uint64_t v, intptr_t slide) {
        if (!found && !strcmp(n, name)) found = (void *)(v + slide);
    });
    return found;
}

static std::string Demangle(const char *sym) {
    if (sym[0] == '_') sym++;
    int st = 0;
    char *d = abi::__cxa_demangle(sym, nullptr, nullptr, &st);
    std::string r = (st == 0 && d) ? d : sym;
    free(d);
    return r;
}

static std::vector<SymHit> SearchSymbols(const char *needle, size_t maxHits) {
    std::vector<SymHit> out;
    ForEachSymbol([&](const char *n, uint64_t v, intptr_t) {
        if (out.size() >= maxHits) return;
        std::string pretty = Demangle(n);
        if (strstr(n, needle) || strstr(pretty.c_str(), needle))
            out.push_back({n, pretty, v});
    });
    return out;
}

// ---------------------------------------------------------------------------
// Game Function Pointers & Global Variables
// ---------------------------------------------------------------------------

typedef void (*GetPosition_t)(TA::Vec3 *out, void *self);
static GetPosition_t p_GetNosePos = nullptr;
static GetPosition_t p_GetTailPos = nullptr;

typedef void (*ProjectPoint_t)(TA::Vec2 *out, const TA::Vec3 *in);
static ProjectPoint_t p_ProjectPointToScreen = nullptr;

static void   **p_g_pDynamicObjectSkateboard = nullptr;
static void   **p_s_pPhysics                 = nullptr;

// ---------------------------------------------------------------------------
// Hooks State
// ---------------------------------------------------------------------------

static struct {
    bool physFound     = false;
    bool physHooked    = false;
    int  physCalls     = 0;
    bool tcFound       = false;   // GetTrueCreditsTotal
    bool tcHooked      = false;
    bool addTcFound    = false;   // AddTrueCredits
    bool subDiyHook    = false;   // IsSubscribedToDIYPlus
    bool subCurHook    = false;   // IsCurrentSubscription
    bool addTrickHook  = false;   // Game::AddTrick
    bool trickFlag     = false;   // _g_bTrickWasSlowMo resolved
    bool notifHook     = false;   // SlowMoNotification_Update
    bool parkOwnHook   = false;   // IsParkOwnedAndIfNotShowPopup
    bool parkPurHook   = false;   // IsParkPurchased
    bool parkKeyHook   = false;   // IsParkUnlockedWithKey
    bool camHooked     = false;   // Camera::SetViewParameters
    bool skyHooked     = false;   // SkyHemiCube::Render
    bool dynSkateFound = false;   // _g_pDynamicObjectSkateboard
    bool physicsFound  = false;   // TA::Physics::s_pPhysics
} gS;

// --- Unlock all parks ---
static bool g_unlockParks = true;

static bool (*orig_ParkOwned)(void *self, int idx) = nullptr;
static bool hook_ParkOwned(void *self, int idx) {
    if (g_unlockParks) return true;
    return orig_ParkOwned(self, idx);
}
static bool (*orig_ParkPurch)(void *self, int idx) = nullptr;
static bool hook_ParkPurch(void *self, int idx) {
    if (g_unlockParks) return true;
    return orig_ParkPurch(self, idx);
}
static bool (*orig_ParkKey)(void *self, int key) = nullptr;
static bool hook_ParkKey(void *self, int key) {
    if (g_unlockParks) return true;
    return orig_ParkKey(self, key);
}

// --- Slow-motion tweaks ---
static bool    g_scoreInSlowMo = true;
static bool    g_hideSlowMoHud = true;
static uint8_t *p_bTrickWasSlowMo = nullptr;

static int (*orig_AddTrick)(void *self, int id) = nullptr;
static int hook_AddTrick(void *self, int id) {
    if (g_scoreInSlowMo && p_bTrickWasSlowMo) *p_bTrickWasSlowMo = 0;
    return orig_AddTrick(self, id);
}

static void (*orig_SlowMoNotif)(float f) = nullptr;
static void hook_SlowMoNotif(float f) {
    if (g_hideSlowMoHud) return;
    orig_SlowMoNotif(f);
}

// --- Sandbox subscription unlock ---
static bool g_forceSub = true;

static bool (*orig_IsSubDIY)(void *self) = nullptr;
static bool hook_IsSubDIY(void *self) {
    if (g_forceSub) return true;
    return orig_IsSubDIY(self);
}

static bool (*orig_IsCurSub)(void *self, const char *id) = nullptr;
static bool hook_IsCurSub(void *self, const char *id) {
    if (g_forceSub) return true;
    return orig_IsCurSub(self, id);
}

// Forward declare physics updater
static void UpdatePhysicsModulations();

static void (*orig_OverridePhysics)(void *self) = nullptr;
static void hook_OverridePhysics(void *self) {
    gS.physCalls++;
    orig_OverridePhysics(self);
    UpdatePhysicsModulations();
}

// --- Currency (TrueCredits) ---
typedef void (*AddTC_t)(void *self, int amount, bool flag);
static void      *g_pUserData  = nullptr;
static AddTC_t    p_AddTC      = nullptr;
static int        g_lastTC     = -1;

static int (*orig_GetTC)(void *self) = nullptr;
static int hook_GetTC(void *self) {
    g_pUserData = self;
    int r = orig_GetTC(self);
    g_lastTC = r;
    return r;
}

static bool AddTrueCredits(int amount) {
    if (!g_pUserData || !p_AddTC) return false;
    p_AddTC(g_pUserData, amount, true);
    return true;
}

// --- Auto-grind (code patch) ---
static bool g_autoGrind = true;

struct PatchSite { uint32_t *addr; uint32_t orig; uint32_t patched; };
static PatchSite g_grindSites[12];
static int  g_grindSiteCount = 0;
static bool g_grindFound = false;

static void WriteWord(uint32_t *addr, uint32_t word) {
    vm_address_t page = (vm_address_t)addr & ~((vm_address_t)vm_page_size - 1);
    if (vm_protect(mach_task_self(), page, vm_page_size, false,
                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS)
        return;
    *addr = word;
    vm_protect(mach_task_self(), page, vm_page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate(addr, sizeof(uint32_t));
}

static void FindGrindThreshold(const char *sym) {
    uint32_t *fn = (uint32_t *)FindSymbol(sym);
    if (!fn) return;
    for (int i = 1; i < 0x180 && g_grindSiteCount + 2 <= 12; i++) {
        uint32_t w = fn[i];
        if ((w & 0xFFFFFFE0) != 0x72A7EFA0) continue;          // movk w?,#0x3f7d,lsl#16
        uint32_t rd = w & 0x1F;
        uint32_t prev = fn[i - 1];
        if ((prev & 0xFFFFFFE0) != 0x528E1480 || (prev & 0x1F) != rd) continue; // movz w?,#0x70a4
        uint32_t newMovz = 0x52800000 | rd;                        // movz wRd,#0
        uint32_t newMovk = 0x72800000 | 0x200000 | (0x4000u << 5) | rd; // movk wRd,#0x4000,lsl#16
        g_grindSites[g_grindSiteCount++] = { &fn[i - 1], prev, newMovz };
        g_grindSites[g_grindSiteCount++] = { &fn[i],     w,    newMovk };
        g_grindFound = true;
    }
}

static void ApplyGrind(bool on) {
    for (int i = 0; i < g_grindSiteCount; i++)
        WriteWord(g_grindSites[i].addr, on ? g_grindSites[i].patched : g_grindSites[i].orig);
}

// ---------------------------------------------------------------------------
// Camera & Visuals Hooks
// ---------------------------------------------------------------------------

static bool  g_customFovEnabled = false;
static float g_customFov        = 75.0f;
static float g_camDistMult      = 1.0f;
static float g_camHeightOffset  = 0.0f;

static TA::Vec3 g_camPos;
static TA::Vec3 g_camTarget;
static float    g_camFov = 65.0f;
static bool     g_camCaptured = false;

static void (*orig_SetViewParameters)(void *self, float *pFov, TA::Vec3 *pPos, TA::Vec3 *pTarget) = nullptr;
static void hook_SetViewParameters(void *self, float *pFov, TA::Vec3 *pPos, TA::Vec3 *pTarget) {
    orig_SetViewParameters(self, pFov, pPos, pTarget);
    if (pFov && pPos && pTarget) {
        if (g_customFovEnabled) {
            *pFov = g_customFov;
        }
        if (fabsf(g_camDistMult - 1.0f) > 0.01f) {
            TA::Vec3 dir = *pPos - *pTarget;
            *pPos = *pTarget + dir * g_camDistMult;
        }
        if (fabsf(g_camHeightOffset) > 0.01f) {
            pPos->y += g_camHeightOffset;
        }

        g_camFov = *pFov;
        g_camPos = *pPos;
        g_camTarget = *pTarget;
        g_camCaptured = true;
    }
}

static bool g_disableSkybox = false;
static void (*orig_SkyHemiCube_Render)(void *self) = nullptr;
static void hook_SkyHemiCube_Render(void *self) {
    if (g_disableSkybox) return;
    orig_SkyHemiCube_Render(self);
}

// ---------------------------------------------------------------------------
// Features Configuration State
// ---------------------------------------------------------------------------

// 1. Skateboard ESP
static bool  g_espEnabled   = true;
static bool  g_esp3DBox     = true;
static bool  g_esp2DBox     = false;
static bool  g_espSnapline  = true;
static bool  g_espHeading   = true;
static bool  g_espNoseTail  = true;
static bool  g_espInfo      = true;
static bool  g_espRainbow   = false;
static float g_espColor[4]  = { 0.0f, 1.0f, 0.85f, 1.0f };
static float g_espThickness = 2.0f;

// 2. Real 3D Chams (Skateboard)
static bool  g_chamsEnabled   = true;
static bool  g_chamsDeck      = true;
static bool  g_chamsWheels    = true;
static bool  g_chamsRainbow   = false;
static bool  g_chamsWireframe = false;
static float g_chamsColor[4]  = { 0.0f, 0.95f, 1.0f, 0.70f };
static float g_chamsWheelCol[4] = { 1.0f, 0.15f, 0.65f, 0.85f };
static float g_chamsAlpha     = 0.75f;

// 3. Player / Skater ESP
static bool  g_skaterEspEnabled = true;
static bool  g_skaterSkeleton   = true;
static bool  g_skater3DBox      = true;
static bool  g_skaterHead       = true;
static bool  g_skaterTag        = true;
static bool  g_skaterRainbow    = false;
static float g_skaterColor[4]   = { 0.95f, 0.35f, 0.95f, 1.0f };

// 4. Rainbow Motion Trails (Tron Ribbon)
static bool g_trailEnabled  = true;
static int  g_trailLength   = 35;
static bool g_trailRainbow  = true;

struct TrailPoint {
    TA::Vec3 nose;
    TA::Vec3 tail;
    TA::Vec3 center;
    bool valid;
};
static const int MAX_TRAIL = 60;
static TrailPoint g_trail[MAX_TRAIL];
static int g_trailHead = 0;
static int g_trailCount = 0;

// 5. Anti-Aim / Spinbot for Skateboard
// 0: Off, 1: Spinbot 360 (Yaw), 2: HVH Jitter, 3: Helicopter, 4: Chaos Shake
static int   g_aaMode       = 0;
static float g_spinbotSpeed = 45.0f;

// 6. Fun Physics & Gravity Hacks
static bool  g_customGravityEnabled = false;
static float g_customGravityY       = -2.0f; // Moon gravity by default
static float g_megaJumpForce        = 13.0f; // Velocity Y boost
static float g_speedBoostAmount     = 16.0f; // Forward boost
static bool  g_freezeAir            = false;
static bool  g_triggerMegaJump      = false;
static bool  g_triggerSpeedBoost    = false;

// 7. Fog & Atmosphere
static bool  g_fogEnabled       = false;
static float g_fogColor[4]      = { 0.04f, 0.05f, 0.12f, 0.40f };
static float g_fogDensity       = 0.6f;

// ---------------------------------------------------------------------------
// World To Screen Projection
// ---------------------------------------------------------------------------

static bool WorldToScreen(const TA::Vec3 &worldPos, ImVec2 &outScreen, const ImVec2 &dispSize) {
    if (!g_camCaptured) return false;

    TA::Vec3 toPt = worldPos - g_camPos;
    TA::Vec3 camFwd = (g_camTarget - g_camPos).Normalized();
    float zDist = TA::Vec3::Dot(toPt, camFwd);
    if (zDist <= 0.08f) return false; // Behind camera clipping

    // 1. Try game's built-in ProjectPointToScreen
    if (p_ProjectPointToScreen) {
        TA::Vec2 ndc = { 0.0f, 0.0f };
        p_ProjectPointToScreen(&ndc, &worldPos);
        if (ndc.x != 0.0f || ndc.y != 0.0f) {
            outScreen.x = (ndc.x + 1.0f) * 0.5f * dispSize.x;
            outScreen.y = (1.0f - ndc.y) * 0.5f * dispSize.y;
            return true;
        }
    }

    // 2. Mathematical camera perspective projection fallback
    TA::Vec3 worldUp(0.0f, 1.0f, 0.0f);
    TA::Vec3 camRight = TA::Vec3::Cross(camFwd, worldUp).Normalized();
    if (camRight.Length() < 0.001f) camRight = TA::Vec3(1.0f, 0.0f, 0.0f);
    TA::Vec3 camUp = TA::Vec3::Cross(camRight, camFwd).Normalized();

    float viewX = TA::Vec3::Dot(toPt, camRight);
    float viewY = TA::Vec3::Dot(toPt, camUp);

    float aspect = dispSize.x / (dispSize.y > 0.0f ? dispSize.y : 1.0f);
    float halfFovRad = (g_camFov * 0.5f) * (3.1415926535f / 180.0f);
    float tanHalfFov = tanf(halfFovRad);

    float ndcX = viewX / (zDist * tanHalfFov * aspect);
    float ndcY = viewY / (zDist * tanHalfFov);

    outScreen.x = (ndcX + 1.0f) * 0.5f * dispSize.x;
    outScreen.y = (1.0f - ndcY) * 0.5f * dispSize.y;
    return true;
}

// ---------------------------------------------------------------------------
// Physics & Anti-Aim Modulations
// ---------------------------------------------------------------------------

static void UpdatePhysicsModulations() {
    // 1. Custom Gravity
    if (p_s_pPhysics && *p_s_pPhysics) {
        float *pPhys = (float *)(*p_s_pPhysics);
        if (g_customGravityEnabled) {
            pPhys[1] = g_customGravityY;
            pPhys[4] = fabsf(g_customGravityY);
        } else {
            pPhys[1] = -9.80665f;
            pPhys[4] = 9.80665f;
        }
    }

    // 2. Skateboard Dynamics: Anti-Aim, Jump, Boost, Freeze
    if (!p_g_pDynamicObjectSkateboard || !*p_g_pDynamicObjectSkateboard) return;

    uint8_t *dynObj = (uint8_t *)*p_g_pDynamicObjectSkateboard;
    float *angVel = (float *)(dynObj + 0x318); // wx, wy, wz
    float *linVel = (float *)(dynObj + 0x328); // vx, vy, vz
    TA::Vec3 *pFwd = (TA::Vec3 *)(dynObj + 0x1e8);

    static int s_aaTick = 0;
    s_aaTick++;

    // Anti-Aim modes
    if (g_aaMode == 1) {
        // Spinbot 360 (Mach-speed yaw rotation)
        angVel[1] = g_spinbotSpeed;
    } else if (g_aaMode == 2) {
        // HVH Jitter (Alternating violent angle flips)
        angVel[1] = (s_aaTick % 4 < 2) ? g_spinbotSpeed : -g_spinbotSpeed;
        angVel[0] = (s_aaTick % 6 < 3) ? 22.0f : -22.0f;
    } else if (g_aaMode == 3) {
        // Helicopter (Propeller spin + vertical air hover)
        angVel[1] = 65.0f;
        if (linVel[1] < 0.6f) linVel[1] = 0.6f;
    } else if (g_aaMode == 4) {
        // Chaos Shake
        angVel[0] = ((rand() % 160) - 80) * 0.5f;
        angVel[1] = ((rand() % 200) - 100) * 0.6f;
        angVel[2] = ((rand() % 160) - 80) * 0.5f;
    }

    // Trigger Mega Jump
    if (g_triggerMegaJump) {
        linVel[1] = g_megaJumpForce;
        g_triggerMegaJump = false;
    }

    // Trigger Speed Boost
    if (g_triggerSpeedBoost) {
        linVel[0] += pFwd->x * g_speedBoostAmount;
        linVel[2] += pFwd->z * g_speedBoostAmount;
        g_triggerSpeedBoost = false;
    }

    // Freeze in Air
    if (g_freezeAir) {
        linVel[0] = 0.0f;
        linVel[1] = 0.0f;
        linVel[2] = 0.0f;
        angVel[0] = 0.0f;
        angVel[1] = 0.0f;
        angVel[2] = 0.0f;
    }
}

// ---------------------------------------------------------------------------
// Render: ESP, 3D Chams, Player ESP, Motion Trails
// ---------------------------------------------------------------------------

static void DrawVisualsAndESP() {
    ImDrawList *drawList = ImGui::GetBackgroundDrawList();
    ImVec2 disp = ImGui::GetIO().DisplaySize;

    // Atmospheric Fog / Dark Mood Overlay
    if (g_fogEnabled) {
        ImU32 fogEdge = ImGui::ColorConvertFloat4ToU32(
            ImVec4(g_fogColor[0], g_fogColor[1], g_fogColor[2], g_fogColor[3] * g_fogDensity));
        ImU32 fogCenter = ImGui::ColorConvertFloat4ToU32(
            ImVec4(g_fogColor[0], g_fogColor[1], g_fogColor[2], g_fogColor[3] * g_fogDensity * 0.35f));

        drawList->AddRectFilledMultiColor(ImVec2(0, 0), disp, fogEdge, fogEdge, fogCenter, fogCenter);
        drawList->AddRectFilled(ImVec2(0, 0), disp, fogCenter);
    }

    if (!p_g_pDynamicObjectSkateboard || !*p_g_pDynamicObjectSkateboard) return;

    uint8_t *dynObj = (uint8_t *)*p_g_pDynamicObjectSkateboard;
    TA::Vec3 right = *(TA::Vec3 *)(dynObj + 0x1c8);
    TA::Vec3 up    = *(TA::Vec3 *)(dynObj + 0x1d8);
    TA::Vec3 fwd   = *(TA::Vec3 *)(dynObj + 0x1e8);
    TA::Vec3 pos   = *(TA::Vec3 *)(dynObj + 0x1f8);
    TA::Vec3 vel   = *(TA::Vec3 *)(dynObj + 0x328);

    TA::Vec3 nose = pos + fwd * 0.41f;
    TA::Vec3 tail = pos - fwd * 0.41f;
    if (p_GetNosePos) p_GetNosePos(&nose, dynObj);
    if (p_GetTailPos) p_GetTailPos(&tail, dynObj);

    TA::Vec3 center = (nose + tail) * 0.5f;
    float halfLen = (nose - tail).Length() * 0.5f;
    if (halfLen < 0.20f) halfLen = 0.41f;
    TA::Vec3 boardFwd = (nose - tail).Normalized();

    static float s_globalHue = 0.0f;
    s_globalHue += 0.015f;
    if (s_globalHue > 1.0f) s_globalHue -= 1.0f;

    // -----------------------------------------------------------------------
    // A. Rainbow Motion Trail (Tron Ribbon)
    // -----------------------------------------------------------------------
    if (g_trailEnabled) {
        // Record new trail point if moved
        bool record = false;
        if (g_trailCount == 0) record = true;
        else {
            int lastIdx = (g_trailHead - 1 + MAX_TRAIL) % MAX_TRAIL;
            if ((center - g_trail[lastIdx].center).Length() > 0.035f) record = true;
        }

        if (record) {
            g_trail[g_trailHead] = { nose, tail, center, true };
            g_trailHead = (g_trailHead + 1) % MAX_TRAIL;
            if (g_trailCount < MAX_TRAIL) g_trailCount++;
        }

        int count = (g_trailCount > g_trailLength) ? g_trailLength : g_trailCount;
        for (int i = 0; i < count - 1; i++) {
            int idx0 = (g_trailHead - count + i + MAX_TRAIL) % MAX_TRAIL;
            int idx1 = (g_trailHead - count + i + 1 + MAX_TRAIL) % MAX_TRAIL;
            if (!g_trail[idx0].valid || !g_trail[idx1].valid) continue;

            ImVec2 scNose0, scNose1, scTail0, scTail1;
            if (WorldToScreen(g_trail[idx0].nose, scNose0, disp) &&
                WorldToScreen(g_trail[idx1].nose, scNose1, disp) &&
                WorldToScreen(g_trail[idx0].tail, scTail0, disp) &&
                WorldToScreen(g_trail[idx1].tail, scTail1, disp)) {

                float progress = (float)i / (float)count;
                float alpha = progress * 0.75f;
                float r = 0.0f, g = 0.95f, b = 1.0f;
                if (g_trailRainbow) {
                    float hue = fmodf(s_globalHue + progress * 0.6f, 1.0f);
                    ImGui::ColorConvertHSVtoRGB(hue, 1.0f, 1.0f, r, g, b);
                }

                ImU32 ribbonCol = ImGui::ColorConvertFloat4ToU32(ImVec4(r, g, b, alpha));
                drawList->AddQuadFilled(scNose0, scNose1, scTail1, scTail0, ribbonCol);
                drawList->AddLine(scNose0, scNose1, ImGui::ColorConvertFloat4ToU32(ImVec4(r, g, b, alpha * 1.2f)), 1.5f);
                drawList->AddLine(scTail0, scTail1, ImGui::ColorConvertFloat4ToU32(ImVec4(r, g, b, alpha * 1.2f)), 1.5f);
            }
        }
    }

    // -----------------------------------------------------------------------
    // B. Real 3D Chams (Solid Deck & Wheels Silhouette)
    // -----------------------------------------------------------------------
    if (g_chamsEnabled) {
        float chamsR, chamsG, chamsB;
        if (g_chamsRainbow) {
            ImGui::ColorConvertHSVtoRGB(s_globalHue, 1.0f, 1.0f, chamsR, chamsG, chamsB);
        } else {
            chamsR = g_chamsColor[0]; chamsG = g_chamsColor[1]; chamsB = g_chamsColor[2];
        }
        ImU32 chamsDeckCol = ImGui::ColorConvertFloat4ToU32(ImVec4(chamsR, chamsG, chamsB, g_chamsAlpha));
        ImU32 chamsLineCol = ImGui::ColorConvertFloat4ToU32(ImVec4(chamsR, chamsG, chamsB, 1.0f));

        float hw = 0.105f;
        float hh = 0.040f;

        // 8 points defining top deck contour
        TA::Vec3 deckTop[8] = {
            center + boardFwd * (halfLen * 0.98f) + up * hh,                 // Nose tip
            center + boardFwd * (halfLen * 0.82f) + right * hw + up * hh,   // Nose right
            center + right * hw + up * hh,                                   // Mid right
            center - boardFwd * (halfLen * 0.82f) + right * hw + up * hh,   // Tail right
            center - boardFwd * (halfLen * 0.98f) + up * hh,                 // Tail tip
            center - boardFwd * (halfLen * 0.82f) - right * hw + up * hh,   // Tail left
            center - right * hw + up * hh,                                   // Mid left
            center + boardFwd * (halfLen * 0.82f) - right * hw + up * hh    // Nose left
        };

        ImVec2 scDeckTop[8];
        bool allTopVis = true;
        for (int i = 0; i < 8; i++) {
            if (!WorldToScreen(deckTop[i], scDeckTop[i], disp)) { allTopVis = false; break; }
        }

        if (allTopVis && g_chamsDeck) {
            if (!g_chamsWireframe) {
                drawList->AddConvexPolyFilled(scDeckTop, 8, chamsDeckCol);
            }
            drawList->AddPolyline(scDeckTop, 8, chamsLineCol, ImDrawFlags_Closed, 2.0f);
            // Deck centerline
            drawList->AddLine(scDeckTop[0], scDeckTop[4], chamsLineCol, 1.5f);
        }

        // 4 Wheels Chams
        if (g_chamsWheels) {
            TA::Vec3 wheelPos[4] = {
                center + boardFwd * 0.24f + right * 0.088f - up * 0.048f,
                center + boardFwd * 0.24f - right * 0.088f - up * 0.048f,
                center - boardFwd * 0.24f + right * 0.088f - up * 0.048f,
                center - boardFwd * 0.24f - right * 0.088f - up * 0.048f
            };
            ImU32 wheelCol = ImGui::ColorConvertFloat4ToU32(
                ImVec4(g_chamsWheelCol[0], g_chamsWheelCol[1], g_chamsWheelCol[2], g_chamsWheelCol[3]));
            ImU32 wheelOut = ImGui::ColorConvertFloat4ToU32(
                ImVec4(g_chamsWheelCol[0], g_chamsWheelCol[1], g_chamsWheelCol[2], 1.0f));

            for (int w = 0; w < 4; w++) {
                ImVec2 scW;
                if (WorldToScreen(wheelPos[w], scW, disp)) {
                    drawList->AddCircleFilled(scW, 5.5f, wheelCol);
                    drawList->AddCircle(scW, 6.5f, wheelOut, 12, 1.5f);
                }
            }
            // Axle connecting front & rear wheels
            ImVec2 scW0, scW1, scW2, scW3;
            if (WorldToScreen(wheelPos[0], scW0, disp) && WorldToScreen(wheelPos[1], scW1, disp))
                drawList->AddLine(scW0, scW1, ImColor(220, 220, 220, 200), 2.0f);
            if (WorldToScreen(wheelPos[2], scW2, disp) && WorldToScreen(wheelPos[3], scW3, disp))
                drawList->AddLine(scW2, scW3, ImColor(220, 220, 220, 200), 2.0f);
        }
    }

    // -----------------------------------------------------------------------
    // C. Skateboard ESP (3D/2D Box, Snapline, Info HUD)
    // -----------------------------------------------------------------------
    if (g_espEnabled) {
        ImU32 espColor;
        if (g_espRainbow) {
            float r, g, b;
            ImGui::ColorConvertHSVtoRGB(s_globalHue, 1.0f, 1.0f, r, g, b);
            espColor = ImGui::ColorConvertFloat4ToU32(ImVec4(r, g, b, 1.0f));
        } else {
            espColor = ImGui::ColorConvertFloat4ToU32(ImVec4(g_espColor[0], g_espColor[1], g_espColor[2], g_espColor[3]));
        }

        float hw = 0.105f;
        float hh = 0.045f;
        TA::Vec3 dx = right * hw;
        TA::Vec3 dy = up * hh;
        TA::Vec3 dz = boardFwd * halfLen;

        TA::Vec3 boxCorners[8] = {
            center + dz + dx + dy, // 0: Nose Top Right
            center + dz - dx + dy, // 1: Nose Top Left
            center + dz - dx - dy, // 2: Nose Bottom Left
            center + dz + dx - dy, // 3: Nose Bottom Right
            center - dz + dx + dy, // 4: Tail Top Right
            center - dz - dx + dy, // 5: Tail Top Left
            center - dz - dx - dy, // 6: Tail Bottom Left
            center - dz + dx - dy  // 7: Tail Bottom Right
        };

        ImVec2 screenCorners[8];
        bool cornerVisible[8];
        int visibleCount = 0;
        float minX = 1e9f, maxX = -1e9f, minY = 1e9f, maxY = -1e9f;

        for (int i = 0; i < 8; i++) {
            cornerVisible[i] = WorldToScreen(boxCorners[i], screenCorners[i], disp);
            if (cornerVisible[i]) {
                visibleCount++;
                if (screenCorners[i].x < minX) minX = screenCorners[i].x;
                if (screenCorners[i].x > maxX) maxX = screenCorners[i].x;
                if (screenCorners[i].y < minY) minY = screenCorners[i].y;
                if (screenCorners[i].y > maxY) maxY = screenCorners[i].y;
            }
        }

        ImVec2 scCenter;
        bool centerVis = WorldToScreen(center, scCenter, disp);

        // 3D Box ESP
        if (g_esp3DBox && visibleCount >= 4) {
            auto DrawEdge = [&](int i, int j) {
                if (cornerVisible[i] && cornerVisible[j]) {
                    drawList->AddLine(screenCorners[i], screenCorners[j], espColor, g_espThickness);
                }
            };
            DrawEdge(0, 1); DrawEdge(1, 5); DrawEdge(5, 4); DrawEdge(4, 0);
            DrawEdge(3, 2); DrawEdge(2, 6); DrawEdge(6, 7); DrawEdge(7, 3);
            DrawEdge(0, 3); DrawEdge(1, 2); DrawEdge(5, 6); DrawEdge(4, 7);
            DrawEdge(0, 5); DrawEdge(1, 4);
        }

        // 2D Box ESP
        if (g_esp2DBox && visibleCount >= 4) {
            minX -= 5.0f; maxX += 5.0f;
            minY -= 5.0f; maxY += 5.0f;
            drawList->AddRectFilled(ImVec2(minX, minY), ImVec2(maxX, maxY),
                                    ImGui::ColorConvertFloat4ToU32(ImVec4(0, 0, 0, 0.22f)), 4.0f);
            drawList->AddRect(ImVec2(minX, minY), ImVec2(maxX, maxY), espColor, 4.0f, 0, g_espThickness);
        }

        // Snapline
        if (g_espSnapline && centerVis) {
            drawList->AddLine(ImVec2(disp.x * 0.5f, disp.y), scCenter,
                              ImGui::ColorConvertFloat4ToU32(ImVec4(g_espColor[0], g_espColor[1], g_espColor[2], 0.60f)),
                              1.5f);
        }

        // Heading Arrow
        if (g_espHeading) {
            TA::Vec3 headWorld = nose + boardFwd * 0.35f;
            ImVec2 scNose, scHead;
            if (WorldToScreen(nose, scNose, disp) && WorldToScreen(headWorld, scHead, disp)) {
                drawList->AddLine(scNose, scHead, ImColor(255, 230, 0, 255), 2.5f);
                drawList->AddCircleFilled(scHead, 4.0f, ImColor(255, 230, 0, 255));
            }
        }

        // Nose & Tail Markers
        if (g_espNoseTail) {
            ImVec2 scNose, scTail;
            if (WorldToScreen(nose, scNose, disp)) {
                drawList->AddCircleFilled(scNose, 5.0f, ImColor(0, 255, 255, 255));
                drawList->AddCircle(scNose, 6.5f, ImColor(0, 0, 0, 220), 12, 1.5f);
                drawList->AddText(ImVec2(scNose.x + 8, scNose.y - 7), ImColor(0, 255, 255, 255), "NOSE");
            }
            if (WorldToScreen(tail, scTail, disp)) {
                drawList->AddCircleFilled(scTail, 5.0f, ImColor(255, 60, 60, 255));
                drawList->AddCircle(scTail, 6.5f, ImColor(0, 0, 0, 220), 12, 1.5f);
                drawList->AddText(ImVec2(scTail.x + 8, scTail.y - 7), ImColor(255, 60, 60, 255), "TAIL");
            }
        }

        // Skateboard Info HUD (Speed & Distance)
        if (g_espInfo && centerVis) {
            float dist = (center - g_camPos).Length();
            float speedKmh = vel.Length() * 3.6f;
            char infoBuf[128];
            snprintf(infoBuf, sizeof(infoBuf), "%.1f m | %.1f km/h", dist, speedKmh);
            ImVec2 txtSz = ImGui::CalcTextSize(infoBuf);
            ImVec2 txtPos = ImVec2(scCenter.x - txtSz.x * 0.5f, (visibleCount >= 4 ? maxY + 6.0f : scCenter.y + 16.0f));

            drawList->AddRectFilled(ImVec2(txtPos.x - 5, txtPos.y - 2),
                                    ImVec2(txtPos.x + txtSz.x + 5, txtPos.y + txtSz.y + 2),
                                    ImColor(0, 0, 0, 200), 4.0f);
            drawList->AddText(txtPos, ImColor(255, 255, 255, 255), infoBuf);
        }
    }

    // -----------------------------------------------------------------------
    // D. Player / Skater ESP (Skeleton, 3D Box, Head Marker, Tags)
    // -----------------------------------------------------------------------
    if (g_skaterEspEnabled) {
        ImU32 skaterColor;
        if (g_skaterRainbow) {
            float r, g, b;
            ImGui::ColorConvertHSVtoRGB(fmodf(s_globalHue + 0.5f, 1.0f), 1.0f, 1.0f, r, g, b);
            skaterColor = ImGui::ColorConvertFloat4ToU32(ImVec4(r, g, b, 1.0f));
        } else {
            skaterColor = ImGui::ColorConvertFloat4ToU32(
                ImVec4(g_skaterColor[0], g_skaterColor[1], g_skaterColor[2], g_skaterColor[3]));
        }

        TA::Vec3 boardUp = up.Normalized();
        TA::Vec3 boardRight = right.Normalized();

        // Skater anatomical joint positions relative to board
        TA::Vec3 ptHead     = center + boardUp * 1.68f;
        TA::Vec3 ptNeck     = center + boardUp * 1.48f;
        TA::Vec3 ptPelvis   = center + boardUp * 0.85f;
        TA::Vec3 ptLShoulder= center + boardUp * 1.42f - boardRight * 0.20f;
        TA::Vec3 ptRShoulder= center + boardUp * 1.42f + boardRight * 0.20f;
        TA::Vec3 ptLHand    = center + boardUp * 1.10f - boardRight * 0.35f;
        TA::Vec3 ptRHand    = center + boardUp * 1.10f + boardRight * 0.35f;
        TA::Vec3 ptLKnee    = center + boardFwd * 0.12f - boardRight * 0.10f + boardUp * 0.45f;
        TA::Vec3 ptRKnee    = center - boardFwd * 0.15f + boardRight * 0.07f + boardUp * 0.45f;
        TA::Vec3 ptFrontFoot= center + boardFwd * 0.22f - boardRight * 0.08f + boardUp * 0.06f;
        TA::Vec3 ptBackFoot = center - boardFwd * 0.28f + boardRight * 0.06f + boardUp * 0.06f;

        ImVec2 scHead, scNeck, scPelvis, scLSh, scRSh, scLH, scRH, scLK, scRK, scFF, scBF;
        bool bHead = WorldToScreen(ptHead, scHead, disp);
        bool bNeck = WorldToScreen(ptNeck, scNeck, disp);
        bool bPelvis = WorldToScreen(ptPelvis, scPelvis, disp);
        bool bLSh = WorldToScreen(ptLShoulder, scLSh, disp);
        bool bRSh = WorldToScreen(ptRShoulder, scRSh, disp);
        bool bLH = WorldToScreen(ptLHand, scLH, disp);
        bool bRH = WorldToScreen(ptRHand, scRH, disp);
        bool bLK = WorldToScreen(ptLKnee, scLK, disp);
        bool bRK = WorldToScreen(ptRKnee, scRK, disp);
        bool bFF = WorldToScreen(ptFrontFoot, scFF, disp);
        bool bBF = WorldToScreen(ptBackFoot, scBF, disp);

        // Skeleton Lines
        if (g_skaterSkeleton) {
            auto Bone = [&](ImVec2 p1, ImVec2 p2, bool v1, bool v2) {
                if (v1 && v2) drawList->AddLine(p1, p2, skaterColor, 2.0f);
            };
            Bone(scHead, scNeck, bHead, bNeck);
            Bone(scNeck, scPelvis, bNeck, bPelvis);
            Bone(scNeck, scLSh, bNeck, bLSh);
            Bone(scNeck, scRSh, bNeck, bRSh);
            Bone(scLSh, scLH, bLSh, bLH);
            Bone(scRSh, scRH, bRSh, bRH);
            Bone(scPelvis, scLK, bPelvis, bLK);
            Bone(scPelvis, scRK, bPelvis, bRK);
            Bone(scLK, scFF, bLK, bFF);
            Bone(scRK, scBF, bRK, bBF);
        }

        // Head Circle & Marker
        if (g_skaterHead && bHead) {
            drawList->AddCircleFilled(scHead, 7.0f, skaterColor);
            drawList->AddCircle(scHead, 8.5f, ImColor(0, 0, 0, 220), 12, 1.5f);
        }

        // Skater 3D Box
        if (g_skater3DBox) {
            float sHW = 0.30f;
            float sHL = 0.25f;
            TA::Vec3 sCenter = center + boardUp * 0.90f;
            TA::Vec3 sBox[8] = {
                sCenter + boardUp * 0.90f + boardRight * sHW + boardFwd * sHL,
                sCenter + boardUp * 0.90f - boardRight * sHW + boardFwd * sHL,
                sCenter + boardUp * 0.90f - boardRight * sHW - boardFwd * sHL,
                sCenter + boardUp * 0.90f + boardRight * sHW - boardFwd * sHL,
                sCenter - boardUp * 0.90f + boardRight * sHW + boardFwd * sHL,
                sCenter - boardUp * 0.90f - boardRight * sHW + boardFwd * sHL,
                sCenter - boardUp * 0.90f - boardRight * sHW - boardFwd * sHL,
                sCenter - boardUp * 0.90f + boardRight * sHW - boardFwd * sHL
            };
            ImVec2 scSBox[8];
            bool sBoxVis[8];
            int sVisCount = 0;
            for (int i = 0; i < 8; i++) {
                sBoxVis[i] = WorldToScreen(sBox[i], scSBox[i], disp);
                if (sBoxVis[i]) sVisCount++;
            }
            if (sVisCount >= 4) {
                auto SEdge = [&](int i, int j) {
                    if (sBoxVis[i] && sBoxVis[j])
                        drawList->AddLine(scSBox[i], scSBox[j], skaterColor, 1.5f);
                };
                SEdge(0, 1); SEdge(1, 2); SEdge(2, 3); SEdge(3, 0);
                SEdge(4, 5); SEdge(5, 6); SEdge(6, 7); SEdge(7, 4);
                SEdge(0, 4); SEdge(1, 5); SEdge(2, 6); SEdge(3, 7);
            }
        }

        // Skater Tag / HUD
        if (g_skaterTag && bHead) {
            const char *tagText = "SKATER [RIDER]";
            ImVec2 tagSz = ImGui::CalcTextSize(tagText);
            ImVec2 tagPos = ImVec2(scHead.x - tagSz.x * 0.5f, scHead.y - 24.0f);
            drawList->AddRectFilled(ImVec2(tagPos.x - 4, tagPos.y - 2),
                                    ImVec2(tagPos.x + tagSz.x + 4, tagPos.y + tagSz.y + 2),
                                    ImColor(0, 0, 0, 190), 3.0f);
            drawList->AddText(tagPos, skaterColor, tagText);
        }
    }
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

static void InstallHooks() {
    void *a = FindSymbol("__ZN4Game32OverridePhysicsSettingsFromStatsEv");
    gS.physFound = (a != nullptr);
    if (a) {
        MSHookFunction(a, (void *)hook_OverridePhysics, (void **)&orig_OverridePhysics);
        gS.physHooked = (orig_OverridePhysics != nullptr);
    }

    void *g = FindSymbol("__ZN24UserDataManagerTrueSkate19GetTrueCreditsTotalEv");
    gS.tcFound = (g != nullptr);
    if (g) {
        MSHookFunction(g, (void *)hook_GetTC, (void **)&orig_GetTC);
        gS.tcHooked = (orig_GetTC != nullptr);
    }
    p_AddTC = (AddTC_t)FindSymbol("__ZN24UserDataManagerTrueSkate14AddTrueCreditsEib");
    gS.addTcFound = (p_AddTC != nullptr);

    void *s1 = FindSymbol("__ZN24UserDataManagerTrueSkate21IsSubscribedToDIYPlusEv");
    if (s1) {
        MSHookFunction(s1, (void *)hook_IsSubDIY, (void **)&orig_IsSubDIY);
        gS.subDiyHook = (orig_IsSubDIY != nullptr);
    }
    void *s2 = FindSymbol("__ZN24UserDataManagerTrueSkate21IsCurrentSubscriptionEPKc");
    if (s2) {
        MSHookFunction(s2, (void *)hook_IsCurSub, (void **)&orig_IsCurSub);
        gS.subCurHook = (orig_IsCurSub != nullptr);
    }

    p_bTrickWasSlowMo = (uint8_t *)FindSymbol("_g_bTrickWasSlowMo");
    gS.trickFlag = (p_bTrickWasSlowMo != nullptr);
    void *at = FindSymbol("__ZN4Game8AddTrickEi");
    if (at) {
        MSHookFunction(at, (void *)hook_AddTrick, (void **)&orig_AddTrick);
        gS.addTrickHook = (orig_AddTrick != nullptr);
    }
    void *sn = FindSymbol("__Z25SlowMoNotification_Updatef");
    if (sn) {
        MSHookFunction(sn, (void *)hook_SlowMoNotif, (void **)&orig_SlowMoNotif);
        gS.notifHook = (orig_SlowMoNotif != nullptr);
    }

    void *po = FindSymbol("__ZN17UiFormSkateparksX28IsParkOwnedAndIfNotShowPopupEi");
    if (po) {
        MSHookFunction(po, (void *)hook_ParkOwned, (void **)&orig_ParkOwned);
        gS.parkOwnHook = (orig_ParkOwned != nullptr);
    }
    void *pp = FindSymbol("__ZN17UiFormSkateparksX15IsParkPurchasedEi");
    if (pp) {
        MSHookFunction(pp, (void *)hook_ParkPurch, (void **)&orig_ParkPurch);
        gS.parkPurHook = (orig_ParkPurch != nullptr);
    }
    void *pk = FindSymbol("__ZN24UserDataManagerTrueSkate21IsParkUnlockedWithKeyEi");
    if (pk) {
        MSHookFunction(pk, (void *)hook_ParkKey, (void **)&orig_ParkKey);
        gS.parkKeyHook = (orig_ParkKey != nullptr);
    }

    // Camera hook
    void *camSym = FindSymbol("__ZN6Camera17SetViewParametersERfRN2TA4Vec3ES3_");
    if (camSym) {
        MSHookFunction(camSym, (void *)hook_SetViewParameters, (void **)&orig_SetViewParameters);
        gS.camHooked = (orig_SetViewParameters != nullptr);
    }

    // Skybox hook
    void *skySym = FindSymbol("__ZN11SkyHemiCube6RenderEv");
    if (skySym) {
        MSHookFunction(skySym, (void *)hook_SkyHemiCube_Render, (void **)&orig_SkyHemiCube_Render);
        gS.skyHooked = (orig_SkyHemiCube_Render != nullptr);
    }

    // Skateboard positions and dynamic pointers
    p_GetNosePos = (GetPosition_t)FindSymbol("__ZN2TA23DynamicObjectSkateboard20GetWorldNosePositionEv");
    p_GetTailPos = (GetPosition_t)FindSymbol("__ZN2TA23DynamicObjectSkateboard20GetWorldTailPositionEv");
    p_ProjectPointToScreen = (ProjectPoint_t)FindSymbol("__Z20ProjectPointToScreenRKN2TA4Vec3E");

    p_g_pDynamicObjectSkateboard = (void **)FindSymbol("_g_pDynamicObjectSkateboard");
    gS.dynSkateFound = (p_g_pDynamicObjectSkateboard != nullptr);
    p_s_pPhysics     = (void **)FindSymbol("__ZN2TA7Physics10s_pPhysicsE");
    gS.physicsFound  = (p_s_pPhysics != nullptr);

    FindGrindThreshold("__ZN4Game25LockTailOrNoseSlideToRailERKN2TA4Vec3Efb");
    FindGrindThreshold("__ZN4Game19LockTailSlideToRailERN2TA4Vec3Eb");
    FindGrindThreshold("__ZN4Game19LockNoseSlideToRailERN2TA4Vec3Eb");
    ApplyGrind(g_autoGrind);
}

// ---------------------------------------------------------------------------
// Menu & Touch Interaction
// ---------------------------------------------------------------------------

static bool   g_menuOpen = false;
static CGRect gMenuRect = CGRectZero;       // points, updated every frame; used for touch passthrough
static CGRect gLastMenuRect = CGRectZero;   // remembered while hidden so the first tap after opening lands

// Touch scrolling and gesture arbitration state
static bool    g_isTouching     = false;
static bool    g_isScrolling    = false;
static bool    g_sliderActive   = false;
static CGPoint g_touchStartPos  = CGPointZero;
static CGPoint g_lastTouchPos   = CGPointZero;
static float   g_pendingScrollY = 0.0f;

static void TouchScroll() {
    if (!g_isScrolling || g_pendingScrollY == 0.0f) return;
    if (!ImGui::IsWindowHovered()) return;
    ImGui::SetScrollY(ImGui::GetScrollY() - g_pendingScrollY);
    g_pendingScrollY = 0.0f;
}

static std::vector<SymHit> gHits;
static std::string gLastQuery;
static void (^gPromptSearch)(void) = nil;

static void RunSearch(const char *q) {
    gLastQuery = q;
    gHits = SearchSymbols(q, 60);
}

static void DrawMenuWindow() {
    g_sliderActive = false;

    ImVec2 disp = ImGui::GetIO().DisplaySize;
    float w = disp.x - 32.0f;
    if (w > 640.0f) w = 640.0f;
    if (w < 280.0f) w = disp.x;

    float h = disp.y * 0.78f;
    if (h > 560.0f) h = 560.0f;

    ImGui::SetNextWindowSize(ImVec2(w, h), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2((disp.x - w) * 0.5f, (disp.y - h) * 0.5f), ImGuiCond_FirstUseEver);

    ImGuiWindowFlags winFlags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar;

    if (ImGui::Begin("TrueSkate Mod Menu", nullptr, winFlags)) {
        ImVec2 pos = ImGui::GetWindowPos(), sz = ImGui::GetWindowSize();
        gMenuRect = CGRectMake(pos.x, pos.y, sz.x, sz.y);

        if (ImGui::BeginTabBar("tabs", ImGuiTabBarFlags_FittingPolicyScroll |
                                       ImGuiTabBarFlags_TabListPopupButton)) {

            // ===============================================================
            // TAB 1: Visuals (ESP, 3D Chams, Player ESP, Trails, Camera)
            // ===============================================================
            if (ImGui::BeginTabItem("Visuals")) {
                ImGui::BeginChild("tab_visuals_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);
                TouchScroll();

                // Section: Skateboard ESP
                if (ImGui::CollapsingHeader("Skateboard ESP", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Checkbox("Master Skateboard ESP", &g_espEnabled);
                    ImGui::Checkbox("3D Bounding Box", &g_esp3DBox);
                    ImGui::SameLine();
                    ImGui::Checkbox("2D Box", &g_esp2DBox);
                    ImGui::Checkbox("Snapline", &g_espSnapline);
                    ImGui::SameLine();
                    ImGui::Checkbox("Heading Arrow", &g_espHeading);
                    ImGui::Checkbox("Nose & Tail Points", &g_espNoseTail);
                    ImGui::SameLine();
                    ImGui::Checkbox("Info HUD (Dist/Speed)", &g_espInfo);

                    ImGui::Spacing();
                    ImGui::Checkbox("Rainbow ESP Mode", &g_espRainbow);
                    if (!g_espRainbow) {
                        ImGui::ColorEdit4("ESP Color##board", g_espColor, ImGuiColorEditFlags_NoInputs);
                    }
                    ImGui::SliderFloat("Line Thickness##board", &g_espThickness, 1.0f, 5.0f, "%.1f px");
                    if (ImGui::IsItemActive()) g_sliderActive = true;
                }

                // Section: Real 3D Chams (Deck & Wheels)
                if (ImGui::CollapsingHeader("Real 3D Chams (Skateboard)", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Checkbox("Enable 3D Chams", &g_chamsEnabled);
                    ImGui::Checkbox("Deck Solid Chams", &g_chamsDeck);
                    ImGui::SameLine();
                    ImGui::Checkbox("Wheels Chams", &g_chamsWheels);
                    ImGui::Checkbox("Wireframe Mode", &g_chamsWireframe);
                    ImGui::SameLine();
                    ImGui::Checkbox("Rainbow Chams", &g_chamsRainbow);

                    if (!g_chamsRainbow) {
                        ImGui::ColorEdit4("Deck Color", g_chamsColor, ImGuiColorEditFlags_NoInputs);
                    }
                    ImGui::ColorEdit4("Wheel Color", g_chamsWheelCol, ImGuiColorEditFlags_NoInputs);
                    ImGui::SliderFloat("Chams Opacity", &g_chamsAlpha, 0.2f, 1.0f, "%.2f");
                    if (ImGui::IsItemActive()) g_sliderActive = true;
                }

                // Section: Player / Skater ESP
                if (ImGui::CollapsingHeader("Player ESP (Skater)", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Checkbox("Enable Skater ESP", &g_skaterEspEnabled);
                    ImGui::Checkbox("Skeleton Bones", &g_skaterSkeleton);
                    ImGui::SameLine();
                    ImGui::Checkbox("Skater 3D Box", &g_skater3DBox);
                    ImGui::Checkbox("Head Marker", &g_skaterHead);
                    ImGui::SameLine();
                    ImGui::Checkbox("Skater Tag", &g_skaterTag);

                    ImGui::Checkbox("Rainbow Skater ESP", &g_skaterRainbow);
                    if (!g_skaterRainbow) {
                        ImGui::ColorEdit4("Skater Color", g_skaterColor, ImGuiColorEditFlags_NoInputs);
                    }
                }

                // Section: Motion Trails (Tron Ribbon)
                if (ImGui::CollapsingHeader("Rainbow Motion Trail (Tron Ribbon)", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Checkbox("Enable Motion Ribbon", &g_trailEnabled);
                    ImGui::SameLine();
                    ImGui::Checkbox("Rainbow Trail", &g_trailRainbow);
                    ImGui::SliderInt("Trail Length", &g_trailLength, 10, 50);
                    if (ImGui::IsItemActive()) g_sliderActive = true;
                }

                // Section: Camera Visuals
                if (ImGui::CollapsingHeader("Camera Visuals")) {
                    ImGui::Checkbox("Custom FOV", &g_customFovEnabled);
                    if (g_customFovEnabled) {
                        ImGui::SliderFloat("FOV", &g_customFov, 45.0f, 140.0f, "%.1f deg");
                        if (ImGui::IsItemActive()) g_sliderActive = true;
                    }

                    ImGui::SliderFloat("Camera Distance", &g_camDistMult, 0.4f, 3.0f, "%.2fx");
                    if (ImGui::IsItemActive()) g_sliderActive = true;

                    ImGui::SliderFloat("Camera Height Offset", &g_camHeightOffset, -1.0f, 2.5f, "%.2fm");
                    if (ImGui::IsItemActive()) g_sliderActive = true;
                }

                // Section: World & Atmosphere
                if (ImGui::CollapsingHeader("World & Atmosphere")) {
                    ImGui::Checkbox("Disable Skybox (Void Sky)", &g_disableSkybox);
                    ImGui::Checkbox("Atmospheric Fog / Vignette", &g_fogEnabled);
                    if (g_fogEnabled) {
                        ImGui::SliderFloat("Fog Density", &g_fogDensity, 0.1f, 1.0f, "%.2f");
                        if (ImGui::IsItemActive()) g_sliderActive = true;
                        ImGui::ColorEdit4("Fog Color", g_fogColor, ImGuiColorEditFlags_NoInputs);
                    }
                }

                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            // ===============================================================
            // TAB 2: Troll & HVH (Anti-Aim, Spinbot, Mega Jump, Gravity)
            // ===============================================================
            if (ImGui::BeginTabItem("Troll / HVH")) {
                ImGui::BeginChild("tab_troll_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);
                TouchScroll();

                if (ImGui::CollapsingHeader("Skateboard Anti-Aim / Spinbot", ImGuiTreeNodeFlags_DefaultOpen)) {
                    const char *aaModes[] = { "Off", "Spinbot 360", "HVH Jitter", "Helicopter", "Chaos Shake" };
                    ImGui::Combo("Anti-Aim Mode", &g_aaMode, aaModes, IM_ARRAYSIZE(aaModes));
                    if (g_aaMode > 0) {
                        ImGui::SliderFloat("Spin Speed", &g_spinbotSpeed, -120.0f, 120.0f, "%.0f rad/s");
                        if (ImGui::IsItemActive()) g_sliderActive = true;
                    }
                    ImGui::TextWrapped("Forces high angular velocity on the board so it spins like a blender!");
                }

                if (ImGui::CollapsingHeader("Gravity & Flight Hacks", ImGuiTreeNodeFlags_DefaultOpen)) {
                    ImGui::Checkbox("Custom In-Engine Gravity", &g_customGravityEnabled);
                    if (g_customGravityEnabled) {
                        if (ImGui::Button("Moon (-2.0)"))   g_customGravityY = -2.0f;
                        ImGui::SameLine();
                        if (ImGui::Button("Zero-G (0.0)"))  g_customGravityY = 0.0f;
                        ImGui::SameLine();
                        if (ImGui::Button("Inverted (+9.8)")) g_customGravityY = 9.8f;
                        ImGui::SameLine();
                        if (ImGui::Button("Earth (-9.8)")) g_customGravityY = -9.80665f;

                        ImGui::SliderFloat("Gravity Y", &g_customGravityY, -30.0f, 25.0f, "%.1f m/s^2");
                        if (ImGui::IsItemActive()) g_sliderActive = true;
                    }

                    ImGui::Separator();
                    ImGui::Checkbox("Freeze Mid-Air", &g_freezeAir);
                    ImGui::Spacing();

                    if (ImGui::Button("MEGA JUMP (Launch to Sky!)", ImVec2(-1, 42))) {
                        g_triggerMegaJump = true;
                    }
                    ImGui::SliderFloat("Jump Force", &g_megaJumpForce, 5.0f, 30.0f, "%.1f m/s");
                    if (ImGui::IsItemActive()) g_sliderActive = true;

                    ImGui::Spacing();
                    if (ImGui::Button("SPEED BOOST (Sonic Push!)", ImVec2(-1, 42))) {
                        g_triggerSpeedBoost = true;
                    }
                    ImGui::SliderFloat("Boost Amount", &g_speedBoostAmount, 5.0f, 40.0f, "%.1f m/s");
                    if (ImGui::IsItemActive()) g_sliderActive = true;
                }

                if (ImGui::CollapsingHeader("Auto-Grind (Rail Stick)")) {
                    if (ImGui::Checkbox("Auto-grind (rail stick)", &g_autoGrind))
                        ApplyGrind(g_autoGrind);
                    ImGui::Text("  threshold patch sites: %d", g_grindSiteCount);
                    ImGui::Text("  found: %s", g_grindFound ? "yes" : "NO");
                }

                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            // ===============================================================
            // TAB 3: Parks
            // ===============================================================
            if (ImGui::BeginTabItem("Parks")) {
                ImGui::BeginChild("tab_parks_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);
                TouchScroll();
                ImGui::Checkbox("Unlock all parks", &g_unlockParks);
                ImGui::Spacing();
                ImGui::TextWrapped("Forces park ownership checks to true - no purchase popup, "
                                    "all parks selectable.");
                ImGui::Separator();
                ImGui::Text("  owned-gate : %s", gS.parkOwnHook ? "yes" : "NO");
                ImGui::Text("  purchased  : %s", gS.parkPurHook ? "yes" : "NO");
                ImGui::Text("  key-unlock : %s", gS.parkKeyHook ? "yes" : "NO");
                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            // ===============================================================
            // TAB 4: SlowMo
            // ===============================================================
            if (ImGui::BeginTabItem("SlowMo")) {
                ImGui::BeginChild("tab_slowmo_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);
                TouchScroll();
                ImGui::Checkbox("Score counts in slow-mo", &g_scoreInSlowMo);
                ImGui::TextWrapped("Clears the 'trick was slow-mo' flag so landed tricks give "
                                    "normal points even while time is slowed.");
                ImGui::Separator();
                ImGui::Checkbox("Hide slow-mo indicator", &g_hideSlowMoHud);
                ImGui::TextWrapped("Suppresses the on-screen 'SLOW MO' popup in game and in replays.");
                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            // ===============================================================
            // TAB 5: Sandbox
            // ===============================================================
            if (ImGui::BeginTabItem("Sandbox")) {
                ImGui::BeginChild("tab_sandbox_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);
                TouchScroll();
                ImGui::TextWrapped("Unlocks the Sandbox subscription content (Community, DIY, mods) "
                                    "by forcing the client-side subscription checks to true.");
                ImGui::Separator();
                ImGui::Checkbox("Force subscription active", &g_forceSub);
                ImGui::Text("IsSubscribedToDIYPlus hooked: %s", gS.subDiyHook ? "yes" : "NO");
                ImGui::Text("IsCurrentSubscription hooked: %s", gS.subCurHook ? "yes" : "NO");
                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            // ===============================================================
            // TAB 6: Money
            // ===============================================================
            if (ImGui::BeginTabItem("Money")) {
                ImGui::BeginChild("tab_money_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);
                TouchScroll();
                ImGui::Text("TrueCredits balance: %s",
                            g_lastTC >= 0 ? std::to_string(g_lastTC).c_str() : "(open shop once to read)");
                ImGui::Text("instance captured: %s", g_pUserData ? "yes" : "NO - open shop once");
                ImGui::Text("AddTrueCredits found: %s", gS.addTcFound ? "yes" : "NO");
                ImGui::Separator();

                static int amount = 100000;
                ImGui::SliderInt("amount", &amount, 1000, 1000000);
                if (ImGui::IsItemActive()) g_sliderActive = true;
                ImGui::Spacing();

                bool canAdd = g_pUserData && gS.addTcFound;
                if (!canAdd) ImGui::BeginDisabled();
                if (ImGui::Button("Add credits", ImVec2(-1, 44))) AddTrueCredits(amount);
                if (!canAdd) ImGui::EndDisabled();
                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            // ===============================================================
            // TAB 7: Dev / Info
            // ===============================================================
            if (ImGui::BeginTabItem("Dev")) {
                ImGui::BeginChild("tab_dev_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_AlwaysVerticalScrollbar);
                TouchScroll();
                ImGui::Text("FPS: %.0f", ImGui::GetIO().Framerate);
                ImGui::Text("Camera: %s  Physics: %s  Skateboard: %s",
                            gS.camHooked ? "Y" : "N", gS.physicsFound ? "Y" : "N", gS.dynSkateFound ? "Y" : "N");
                ImGui::Separator();
                static const char *presets[] = {"Game::", "Physics", "Skateboard", "Skater", "Camera", "Trick"};
                for (int i = 0; i < 6; i++) {
                    if (i) ImGui::SameLine();
                    if (ImGui::Button(presets[i])) RunSearch(presets[i]);
                }
                ImGui::Spacing();
                if (ImGui::Button("Custom search...", ImVec2(160, 36)) && gPromptSearch) gPromptSearch();
                ImGui::SameLine();
                ImGui::Text("'%s' (%zu hits)", gLastQuery.c_str(), gHits.size());
                ImGui::Separator();
                ImGui::BeginChild("hits", ImVec2(0, 240), true);
                for (size_t i = 0; i < gHits.size(); i++) {
                    ImGui::PushID((int)i);
                    if (ImGui::SmallButton("copy")) {
                        UIPasteboard.generalPasteboard.string =
                            [NSString stringWithFormat:@"0x%llx %s", gHits[i].vmaddr, gHits[i].pretty.c_str()];
                    }
                    ImGui::SameLine();
                    ImGui::TextWrapped("0x%llx  %s", gHits[i].vmaddr, gHits[i].pretty.c_str());
                    ImGui::PopID();
                }
                TouchScroll();
                ImGui::EndChild();
                ImGui::EndChild();
                ImGui::EndTabItem();
            }

            ImGui::EndTabBar();
        }
    }
    ImGui::End();

    g_pendingScrollY = 0.0f;
}

static void DrawMenu() {
    UpdatePhysicsModulations();
    DrawVisualsAndESP();

    if (g_menuOpen) {
        DrawMenuWindow();
    } else {
        gMenuRect = CGRectZero;
    }
}

// ---------------------------------------------------------------------------
// Overlay Window & Metal View
// ---------------------------------------------------------------------------

@interface TSMView : MTKView
@end

@implementation TSMView

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = touches.anyObject;
    if (!t) return;
    CGPoint p = [t locationInView:self];

    g_isTouching = true;
    g_isScrolling = false;
    g_touchStartPos = p;
    g_lastTouchPos = p;
    g_pendingScrollY = 0.0f;

    ImGuiIO &io = ImGui::GetIO();
    io.AddMouseSourceEvent(ImGuiMouseSource_TouchScreen);
    io.AddMousePosEvent((float)p.x, (float)p.y);
    io.AddMouseButtonEvent(0, true);
}

- (void)touchesMoved:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    UITouch *t = touches.anyObject;
    if (!t || !g_isTouching) return;
    CGPoint p = [t locationInView:self];
    ImGuiIO &io = ImGui::GetIO();

    float dx = (float)(p.x - g_touchStartPos.x);
    float dy = (float)(p.y - g_touchStartPos.y);

    if (!g_isScrolling && !g_sliderActive && fabsf(dy) > 10.0f && fabsf(dy) > fabsf(dx)) {
        g_isScrolling = true;
        io.AddMouseSourceEvent(ImGuiMouseSource_TouchScreen);
        io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);
        io.AddMouseButtonEvent(0, false);
    }

    if (g_isScrolling)
        g_pendingScrollY += (float)(p.y - g_lastTouchPos.y);

    io.AddMouseSourceEvent(ImGuiMouseSource_TouchScreen);
    io.AddMousePosEvent((float)p.x, (float)p.y);
    g_lastTouchPos = p;
}

- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    if (!g_isTouching) return;
    UITouch *t = touches.anyObject;
    CGPoint p = t ? [t locationInView:self] : g_lastTouchPos;

    ImGuiIO &io = ImGui::GetIO();
    io.AddMouseSourceEvent(ImGuiMouseSource_TouchScreen);
    io.AddMousePosEvent((float)p.x, (float)p.y);
    if (!g_isScrolling) io.AddMouseButtonEvent(0, false);

    g_isTouching = false;
    g_isScrolling = false;
}

- (void)touchesCancelled:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    [self touchesEnded:touches withEvent:event];
}

@end

@class TSMController;

@interface TSMWindow : UIWindow
@end

@interface TSMController : UIViewController <MTKViewDelegate>
@property (nonatomic, strong) id<MTLDevice> device;
@property (nonatomic, strong) id<MTLCommandQueue> queue;
@property (nonatomic, strong) TSMView *mtk;
@property (nonatomic, strong) UIButton *toggle;
- (void)toggleMenu;
@end

@implementation TSMWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    TSMController *ctrl = (TSMController *)self.rootViewController;
    if (v == ctrl.toggle) return v;
    if (v == self || v == ctrl.view) return nil;
    if ([v isKindOfClass:[TSMView class]]) {
        // If menu is open and tap is on menu window, let ImGui receive it
        if (g_menuOpen && CGRectContainsPoint(CGRectInset(gMenuRect, -8, -8), point)) {
            return v;
        }
        // Otherwise pass through to True Skate so gameplay is untouched!
        return nil;
    }
    return v;
}
@end

@implementation TSMController

- (void)loadView {
    self.view = [[UIView alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.view.backgroundColor = UIColor.clearColor;
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.device = MTLCreateSystemDefaultDevice();
    self.queue = [self.device newCommandQueue];

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.FontGlobalScale = 1.35f;
    io.ConfigWindowsMoveFromTitleBarOnly = true;

    ImGui::StyleColorsDark();
    ImGuiStyle &style = ImGui::GetStyle();
    style.ScaleAllSizes(1.35f);

    style.TouchExtraPadding = ImVec2(6.0f, 6.0f);
    style.FramePadding      = ImVec2(10.0f, 8.0f);
    style.ItemSpacing       = ImVec2(10.0f, 10.0f);
    style.ItemInnerSpacing  = ImVec2(8.0f, 6.0f);
    style.ScrollbarSize     = 24.0f;
    style.GrabMinSize       = 24.0f;
    style.WindowRounding    = 10.0f;
    style.FrameRounding     = 6.0f;
    style.GrabRounding      = 6.0f;
    style.ScrollbarRounding = 8.0f;
    style.WindowBorderSize  = 1.0f;
    style.FrameBorderSize   = 0.5f;

    ImGui_ImplMetal_Init(self.device);

    self.mtk = [[TSMView alloc] initWithFrame:self.view.bounds device:self.device];
    self.mtk.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.mtk.opaque = NO;
    self.mtk.layer.opaque = NO;
    self.mtk.backgroundColor = UIColor.clearColor;
    self.mtk.clearColor = MTLClearColorMake(0, 0, 0, 0);
    self.mtk.preferredFramesPerSecond = 60;
    self.mtk.delegate = self;
    self.mtk.hidden = NO;  // Run transparently so ESP and Chams render during gameplay
    self.mtk.paused = NO;
    [self.view addSubview:self.mtk];

    self.toggle = [UIButton buttonWithType:UIButtonTypeSystem];
    self.toggle.frame = CGRectMake(20, 120, 48, 48);
    self.toggle.layer.cornerRadius = 24;
    self.toggle.backgroundColor = [UIColor colorWithWhite:0 alpha:0.55];
    self.toggle.tintColor = UIColor.whiteColor;
    [self.toggle setTitle:@"TS" forState:UIControlStateNormal];
    [self.toggle addTarget:self action:@selector(toggleMenu) forControlEvents:UIControlEventTouchUpInside];
    [self.toggle addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(dragToggle:)]];
    [self.view addSubview:self.toggle];

    __weak TSMController *weakSelf = self;
    gPromptSearch = ^{
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"Symbol search"
                                                                    message:@"Substring of a symbol name"
                                                             preferredStyle:UIAlertControllerStyleAlert];
        [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) { tf.autocorrectionType = UITextAutocorrectionTypeNo; tf.autocapitalizationType = UITextAutocapitalizationTypeNone; }];
        [ac addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
        [ac addAction:[UIAlertAction actionWithTitle:@"Search" style:UIAlertActionStyleDefault handler:^(UIAlertAction *) {
            NSString *q = ac.textFields.firstObject.text;
            if (q.length) RunSearch(q.UTF8String);
        }]];
        [weakSelf presentViewController:ac animated:YES completion:nil];
    };
}

- (void)toggleMenu {
    g_menuOpen = !g_menuOpen;
    if (g_menuOpen) {
        self.mtk.hidden = NO;
        self.mtk.paused = NO;
        gMenuRect = gLastMenuRect;
    } else {
        gLastMenuRect = gMenuRect;
        gMenuRect = CGRectZero;
        g_isTouching = false;
        g_isScrolling = false;
        g_pendingScrollY = 0.0f;
        ImGuiIO &io = ImGui::GetIO();
        io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);
        io.AddMouseButtonEvent(0, false);

        // Keep view running if visuals/ESP/chams are active so they draw while skating
        BOOL needsRender = (g_espEnabled || g_chamsEnabled || g_skaterEspEnabled || g_trailEnabled || g_fogEnabled);
        self.mtk.hidden = !needsRender;
        self.mtk.paused = !needsRender;
    }
}

- (void)dragToggle:(UIPanGestureRecognizer *)g {
    CGPoint d = [g translationInView:self.view];
    self.toggle.center = CGPointMake(self.toggle.center.x + d.x, self.toggle.center.y + d.y);
    [g setTranslation:CGPointZero inView:self.view];
}

- (void)mtkView:(MTKView *)view drawableSizeWillChange:(CGSize)size {}

- (void)drawInMTKView:(MTKView *)view {
    MTLRenderPassDescriptor *rpd = view.currentRenderPassDescriptor;
    if (!rpd) return;

    ImGuiIO &io = ImGui::GetIO();
    CGFloat scale = view.window.screen.scale ?: UIScreen.mainScreen.scale;
    io.DisplaySize = ImVec2((float)view.bounds.size.width, (float)view.bounds.size.height);
    io.DisplayFramebufferScale = ImVec2((float)scale, (float)scale);
    io.DeltaTime = 1.0f / 60.0f;

    id<MTLCommandBuffer> cb = [self.queue commandBuffer];
    ImGui_ImplMetal_NewFrame(rpd);
    ImGui::NewFrame();
    DrawMenu();
    ImGui::Render();

    id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rpd];
    ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), cb, enc);
    [enc endEncoding];
    [cb presentDrawable:view.currentDrawable];
    [cb commit];
}
@end

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

static TSMWindow *gWindow = nil;

static void SetupOverlay() {
    if (gWindow) return;

    InstallHooks();

    UIWindowScene *scene = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:UIWindowScene.class]) { scene = (UIWindowScene *)s; break; }
    }
    gWindow = scene ? [[TSMWindow alloc] initWithWindowScene:scene]
                    : [[TSMWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    gWindow.frame = UIScreen.mainScreen.bounds;
    gWindow.windowLevel = UIWindowLevelAlert + 100;
    gWindow.backgroundColor = UIColor.clearColor;
    gWindow.rootViewController = [TSMController new];
    gWindow.hidden = NO;
}

__attribute__((constructor))
static void TSMInit() {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification
                                                       object:nil
                                                        queue:NSOperationQueue.mainQueue
                                                   usingBlock:^(NSNotification *) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ SetupOverlay(); });
    }];
}
