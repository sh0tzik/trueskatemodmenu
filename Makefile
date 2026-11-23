TARGET := iphone:clang:latest:15.0
ARCHS = arm64
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = TrueSkateMenu

IMGUI = vendor/imgui

TrueSkateMenu_FILES = Tweak.mm \
	$(IMGUI)/imgui.cpp \
	$(IMGUI)/imgui_draw.cpp \
	$(IMGUI)/imgui_tables.cpp \
	$(IMGUI)/imgui_widgets.cpp \
	$(IMGUI)/backends/imgui_impl_metal.mm

TrueSkateMenu_CFLAGS = -fobjc-arc -I$(IMGUI) -I$(IMGUI)/backends -Wno-deprecated-declarations
TrueSkateMenu_CCFLAGS = -std=c++17
TrueSkateMenu_FRAMEWORKS = UIKit Metal MetalKit QuartzCore
TrueSkateMenu_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
