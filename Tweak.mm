// TrueSkateMenu - ImGui overlay for True Skate (com.trueaxis.skate), rootless / Dopamine.
// Overlay = separate UIWindow with a transparent MTKView, so we don't touch the game's renderer.

#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <cxxabi.h>
#include <substrate.h>
#include <string>
#include <vector>
#include <cstring>

#include "imgui.h"
#include "imgui_impl_metal.h"

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
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(0);
    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
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
// Hooks
// ---------------------------------------------------------------------------

static struct {
    bool   physFound   = false;
    bool   physHooked  = false;
    int    physCalls   = 0;
    bool   tcFound     = false;   // GetTrueCreditsTotal
    bool   tcHooked    = false;
    bool   addTcFound  = false;   // AddTrueCredits
    bool   subDiyHook  = false;   // IsSubscribedToDIYPlus
    bool   subCurHook  = false;   // IsCurrentSubscription
    bool   addTrickHook = false;  // Game::AddTrick
    bool   trickFlag    = false;  // _g_bTrickWasSlowMo resolved
    bool   notifHook    = false;  // SlowMoNotification_Update
} gS;

// --- Slow-motion tweaks ---
// Score void in slow-mo: Game::AddTrick checks _g_bTrickWasSlowMo and, if set,
// forces the trick's score to 0 (verified in disasm). Clearing the flag right
// before AddTrick scores the trick normally even though time is still slowed.
// Hide indicator: SlowMoNotification_Update only animates the on-screen "SLOW MO"
// popup (no fuel logic), so neutering it hides the indicator in game and replays.
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
// The whole Sandbox / Community / DIY content is gated behind these client-side
// boolean checks. Forcing them true makes the game treat the subscription as active.
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

static void (*orig_OverridePhysics)(void *self) = nullptr;
static void hook_OverridePhysics(void *self) {
    gS.physCalls++;
    orig_OverridePhysics(self);
    // TODO: tweak physics values here once the field layout is reversed.
}

// --- Currency (TrueCredits) ---
// UserDataManagerTrueSkate is a singleton we never get a clean accessor for,
// so we snatch its 'this' from GetTrueCreditsTotal, which the shop/HUD calls a lot.
typedef void (*AddTC_t)(void *self, int amount, bool flag);
static void      *g_pUserData  = nullptr;   // captured instance
static AddTC_t    p_AddTC      = nullptr;
static int        g_lastTC     = -1;        // last read balance, for display

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
}

// ---------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------

static CGRect gMenuRect = CGRectZero;   // points, updated every frame; used for touch passthrough
static std::vector<SymHit> gHits;
static std::string gLastQuery;
static void (^gPromptSearch)(void) = nil;

static void RunSearch(const char *q) {
    gLastQuery = q;
    gHits = SearchSymbols(q, 60);
}

static void DrawMenu() {
    ImGui::SetNextWindowSize(ImVec2(520, 420), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(ImVec2(60, 60), ImGuiCond_FirstUseEver);
    ImGui::Begin("TrueSkate Menu", nullptr, ImGuiWindowFlags_NoCollapse);

    ImVec2 pos = ImGui::GetWindowPos(), sz = ImGui::GetWindowSize();
    gMenuRect = CGRectMake(pos.x, pos.y, sz.x, sz.y);

    if (ImGui::BeginTabBar("tabs")) {
        if (ImGui::BeginTabItem("Info")) {
            ImGui::Text("FPS: %.0f", ImGui::GetIO().Framerate);
            ImGui::Separator();
            ImGui::Text("Game::OverridePhysicsSettingsFromStats");
            ImGui::Text("  found : %s", gS.physFound ? "yes" : "NO");
            ImGui::Text("  hooked: %s", gS.physHooked ? "yes" : "NO");
            ImGui::Text("  calls : %d", gS.physCalls);
            ImGui::Separator();
            ImGui::Text("TrueCredits  found:%s hooked:%s add:%s",
                        gS.tcFound ? "y" : "n", gS.tcHooked ? "y" : "n", gS.addTcFound ? "y" : "n");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("SlowMo")) {
            ImGui::Checkbox("Score counts in slow-mo", &g_scoreInSlowMo);
            ImGui::TextWrapped("Clears the 'trick was slow-mo' flag so landed tricks give "
                               "normal points even while time is slowed.");
            ImGui::Text("  AddTrick hooked: %s   flag found: %s",
                        gS.addTrickHook ? "yes" : "NO", gS.trickFlag ? "yes" : "NO");
            ImGui::Separator();
            ImGui::Checkbox("Hide slow-mo indicator", &g_hideSlowMoHud);
            ImGui::TextWrapped("Suppresses the on-screen 'SLOW MO' popup in game and in replays.");
            ImGui::Text("  Notification hooked: %s", gS.notifHook ? "yes" : "NO");
            ImGui::Separator();
            ImGui::TextWrapped("Reminder: keep these runs local - don't post slow-mo scores or "
                               "replays to leaderboards.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Sandbox")) {
            ImGui::TextWrapped("Unlocks the Sandbox subscription content (Community, DIY, mods) "
                               "by forcing the client-side subscription checks to true.");
            ImGui::Separator();
            ImGui::Checkbox("Force subscription active", &g_forceSub);
            ImGui::Text("IsSubscribedToDIYPlus hooked: %s", gS.subDiyHook ? "yes" : "NO");
            ImGui::Text("IsCurrentSubscription hooked: %s", gS.subCurHook ? "yes" : "NO");
            ImGui::TextWrapped("Toggle off and reopen the menu/form if something behaves oddly.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Money")) {
            ImGui::Text("TrueCredits balance: %s",
                        g_lastTC >= 0 ? std::to_string(g_lastTC).c_str() : "(open shop once to read)");
            ImGui::Text("instance captured: %s", g_pUserData ? "yes" : "NO - open the shop once");
            ImGui::Text("AddTrueCredits found: %s", gS.addTcFound ? "yes" : "NO");
            ImGui::Separator();

            static int amount = 100000;
            ImGui::SliderInt("amount", &amount, 1000, 1000000);
            ImGui::TextWrapped("Keep the total sane. Huge values (~2M+) get clamped or wiped by the game.");

            bool canAdd = g_pUserData && gS.addTcFound;
            if (!canAdd) ImGui::BeginDisabled();
            if (ImGui::Button("Add credits")) AddTrueCredits(amount);
            if (!canAdd) ImGui::EndDisabled();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Physics")) {
            ImGui::TextWrapped("Empty for now. Values appear here once the stats / physics "
                               "structures are reversed (see Dev tab to locate functions).");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Dev")) {
            static const char *presets[] = {"Game::", "Physics", "Skateboard", "Camera", "Unlock", "Trick"};
            for (int i = 0; i < 6; i++) {
                if (i) ImGui::SameLine();
                if (ImGui::Button(presets[i])) RunSearch(presets[i]);
            }
            if (ImGui::Button("Custom search...") && gPromptSearch) gPromptSearch();
            ImGui::SameLine();
            ImGui::Text("'%s'  (%zu hits)", gLastQuery.c_str(), gHits.size());
            ImGui::Separator();
            ImGui::BeginChild("hits", ImVec2(0, 0), true);
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
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Overlay window / Metal view
// ---------------------------------------------------------------------------

@interface TSMView : MTKView
@end

@implementation TSMView
- (void)feed:(NSSet<UITouch *> *)touches down:(int)state {
    UITouch *t = touches.anyObject;
    if (!t) return;
    CGPoint p = [t locationInView:self];
    ImGuiIO &io = ImGui::GetIO();
    io.AddMousePosEvent((float)p.x, (float)p.y);
    if (state == 1) io.AddMouseButtonEvent(0, true);
    if (state == 2) io.AddMouseButtonEvent(0, false);
}
- (void)touchesBegan:(NSSet<UITouch *> *)t withEvent:(UIEvent *)e     { [self feed:t down:1]; }
- (void)touchesMoved:(NSSet<UITouch *> *)t withEvent:(UIEvent *)e     { [self feed:t down:0]; }
- (void)touchesEnded:(NSSet<UITouch *> *)t withEvent:(UIEvent *)e     { [self feed:t down:2]; }
- (void)touchesCancelled:(NSSet<UITouch *> *)t withEvent:(UIEvent *)e { [self feed:t down:2]; }
@end

@interface TSMWindow : UIWindow
@end

@implementation TSMWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    if (v == self || v == self.rootViewController.view) return nil;
    if ([v isKindOfClass:[TSMView class]]) {
        return CGRectContainsPoint(gMenuRect, point) ? v : nil;
    }
    return v;   // the floating toggle button
}
@end

@interface TSMController : UIViewController <MTKViewDelegate>
@property (nonatomic, strong) id<MTLDevice> device;
@property (nonatomic, strong) id<MTLCommandQueue> queue;
@property (nonatomic, strong) TSMView *mtk;
@property (nonatomic, strong) UIButton *toggle;
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
    io.FontGlobalScale = 1.5f;
    ImGui::StyleColorsDark();
    ImGui::GetStyle().ScaleAllSizes(1.5f);
    ImGui_ImplMetal_Init(self.device);

    self.mtk = [[TSMView alloc] initWithFrame:self.view.bounds device:self.device];
    self.mtk.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.mtk.opaque = NO;
    self.mtk.layer.opaque = NO;
    self.mtk.backgroundColor = UIColor.clearColor;
    self.mtk.clearColor = MTLClearColorMake(0, 0, 0, 0);
    self.mtk.preferredFramesPerSecond = 60;
    self.mtk.delegate = self;
    self.mtk.hidden = YES;
    self.mtk.paused = YES;
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
    BOOL show = self.mtk.hidden;
    self.mtk.hidden = !show;
    self.mtk.paused = !show;
    if (!show) gMenuRect = CGRectZero;
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
// Entry
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
